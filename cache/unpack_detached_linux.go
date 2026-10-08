package cache

import (
	"archive/tar"
	"context"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/diff"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/pkg/archive"
	"github.com/containerd/continuity/fs"
	"github.com/containerd/continuity/sysx"
	"github.com/moby/sys/userns"
	digest "github.com/opencontainers/go-digest"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// Detached apply extracts a layer into an empty overlayfs upper directory
// before its parent has been extracted, so the layers of a chain can be
// extracted in parallel. The snapshot is committed onto its parent afterwards
// (snapshots.WithParent), in chain order.
//
// The result must be identical to applying the layer on top of its parent.
// Applying a layer to an overlay upper directory only reads the lower layers
// in one place: when an entry's parent directory is missing from the tar,
// archive.Apply creates it and copies its owner, mode and xattrs from the
// first lower layer that has it (mkparent). Detached apply records which
// directories were created that way and copies the same attributes once the
// parent is available (fixupImplicitDirs).

func detachedApplySupported(snapshotterName string) bool {
	// whiteouts are converted with mknod, which does not work in a user namespace
	return snapshotterName == "overlayfs" && !userns.RunningInUserNS()
}

// layerDirs records how archive.Apply creates directories while it applies a
// layer to an empty directory.
type layerDirs struct {
	// listed holds the directories that have an entry in the tar.
	listed map[string]struct{}
	// implicit holds the directories that were created because an entry
	// needed them as its parent before they had an entry of their own, in
	// creation order.
	implicit []string
	// unsafe is set when the recorded paths may not match the paths that
	// archive.Apply wrote, because an entry's parent path goes through a
	// symlink or a path changed type. The caller then falls back to
	// applying the layer on top of its parent.
	unsafe bool
}

func scanLayerDirs(r io.Reader) (*layerDirs, error) {
	ld := &layerDirs{listed: map[string]struct{}{}}
	// kind of the entry that currently exists at each path
	const (
		kindDir = iota + 1
		kindSymlink
		kindOther
	)
	exists := map[string]int{}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return ld, nil
		}
		if err != nil {
			return nil, err
		}
		name := strings.TrimPrefix(path.Clean("/"+hdr.Name), "/")
		if name == "" {
			continue
		}
		// ancestors, top-down
		var parents []string
		for d := path.Dir(name); d != "." && d != "/"; d = path.Dir(d) {
			parents = append(parents, d)
		}
		for i := len(parents) - 1; i >= 0; i-- {
			d := parents[i]
			switch exists[d] {
			case 0:
				exists[d] = kindDir
				ld.implicit = append(ld.implicit, d)
			case kindDir:
			default:
				ld.unsafe = true
			}
		}
		base := path.Base(name)
		if base == ".wh..wh..opq" {
			continue
		}
		if strings.HasPrefix(base, ".wh.") {
			name = path.Join(path.Dir(name), strings.TrimPrefix(base, ".wh."))
		}
		kind := kindOther
		switch hdr.Typeflag {
		case tar.TypeDir:
			kind = kindDir
			ld.listed[name] = struct{}{}
		case tar.TypeSymlink:
			kind = kindSymlink
		}
		if prev, ok := exists[name]; ok && (prev == kindDir) != (kind == kindDir) {
			// a directory replaced by a file or the other way round
			ld.unsafe = true
		}
		exists[name] = kind
	}
}

// applyToUpper applies desc to the empty upper directory of an overlayfs
// snapshot without a parent. It returns the diffID of the layer and the
// directories that archive.Apply created implicitly.
func applyToUpper(ctx context.Context, cs content.Provider, desc ocispecs.Descriptor, mounts []mount.Mount) (_ digest.Digest, _ *layerDirs, rerr error) {
	if len(mounts) != 1 || mounts[0].Type != "bind" {
		return "", nil, errors.Errorf("unexpected mounts for a snapshot without parent: %+v", mounts)
	}
	upper := mounts[0].Source

	ra, err := cs.ReaderAt(ctx, desc)
	if err != nil {
		return "", nil, errors.Wrap(err, "failed to get reader from content store")
	}
	r := io.NopCloser(content.NewReader(ra))
	defer ra.Close()

	// decompress like the containerd applier does
	processor := diff.NewProcessorChain(desc.MediaType, r)
	for {
		if processor, err = diff.GetProcessor(ctx, processor, nil); err != nil {
			return "", nil, errors.Wrapf(err, "failed to get stream processor for %s", desc.MediaType)
		}
		if processor.MediaType() == ocispecs.MediaTypeImageLayer {
			break
		}
	}
	defer processor.Close()

	digester := digest.Canonical.Digester()
	pr, pw := io.Pipe()
	type scanResult struct {
		ld  *layerDirs
		err error
	}
	scanned := make(chan scanResult, 1)
	go func() {
		ld, err := scanLayerDirs(pr)
		// keep draining so that the applier is never blocked
		_, _ = io.Copy(io.Discard, pr)
		scanned <- scanResult{ld, err}
	}()
	rc := io.TeeReader(processor, io.MultiWriter(digester.Hash(), pw))

	_, err = archive.Apply(ctx, upper, rc, archive.WithConvertWhiteout(archive.OverlayConvertWhiteout))
	if err == nil {
		// read any trailing data
		_, err = io.Copy(io.Discard, rc)
	}
	pw.CloseWithError(err)
	res := <-scanned
	if err != nil {
		return "", nil, err
	}
	if res.err != nil {
		return "", nil, errors.Wrap(res.err, "failed to scan layer")
	}
	return digester.Digest(), res.ld, nil
}

// fixupImplicitDirs gives the directories that archive.Apply created
// implicitly the attributes it would have copied from the lower layers if
// they had been available: owner, mode and non-trusted xattrs of the first
// lower directory that has the path. Directories that the tar lists later
// keep the owner and mode from the tar and only gain missing xattrs.
func fixupImplicitDirs(upper string, lowers []string, ld *layerDirs) error {
	for _, p := range ld.implicit {
		dst := filepath.Join(upper, p)
		fi, err := os.Lstat(dst)
		if err != nil {
			if os.IsNotExist(err) {
				// removed again by a later entry
				continue
			}
			return err
		}
		if !fi.IsDir() {
			continue
		}
		_, listed := ld.listed[p]
		for _, lower := range lowers {
			src, err := fs.RootPath(lower, p)
			if err != nil {
				return err
			}
			sfi, err := os.Lstat(src)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return err
			}
			if !sfi.IsDir() {
				break
			}
			if !listed {
				st := sfi.Sys().(*syscall.Stat_t)
				if err := os.Lchown(dst, int(st.Uid), int(st.Gid)); err != nil {
					return errors.Wrapf(err, "failed to chown %s", dst)
				}
				if err := os.Chmod(dst, sfi.Mode()); err != nil {
					return errors.Wrapf(err, "failed to chmod %s", dst)
				}
			}
			if err := copyUpXAttrs(dst, src); err != nil {
				return err
			}
			break
		}
	}
	return nil
}

// copyUpXAttrs matches archive.copyUpXAttrs.
func copyUpXAttrs(dst, src string) error {
	keys, err := sysx.LListxattr(src)
	if err != nil {
		if err == unix.ENOTSUP || err == sysx.ENODATA {
			return nil
		}
		return errors.Wrapf(err, "failed to list xattrs on %s", src)
	}
	for _, k := range keys {
		if strings.HasPrefix(k, "trusted.") {
			continue
		}
		data, err := sysx.LGetxattr(src, k)
		if err != nil {
			if err == unix.ENOTSUP || err == sysx.ENODATA {
				continue
			}
			return errors.Wrapf(err, "failed to get xattr %q on %s", k, src)
		}
		if err := unix.Lsetxattr(dst, k, data, unix.XATTR_CREATE); err != nil && err != unix.ENOTSUP && err != unix.ENODATA && err != unix.EEXIST {
			return errors.Wrapf(err, "failed to set xattr %q on %s", k, dst)
		}
	}
	return nil
}

// lowerDirs returns the directories of a read-only view of a snapshot,
// topmost first.
func lowerDirs(mounts []mount.Mount) ([]string, error) {
	if len(mounts) == 1 {
		switch mounts[0].Type {
		case "bind":
			return []string{mounts[0].Source}, nil
		case "overlay":
			for _, o := range mounts[0].Options {
				if v, ok := strings.CutPrefix(o, "lowerdir="); ok {
					return strings.Split(v, ":"), nil
				}
			}
		}
	}
	return nil, errors.Errorf("unexpected mounts for a parent view: %+v", mounts)
}
