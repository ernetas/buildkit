package cache

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/labels"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/plugins/snapshots/overlay"
	"github.com/containerd/containerd/v2/plugins/snapshots/overlay/overlayutils"
	"github.com/containerd/continuity/sysx"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/util/contentutil"
	digest "github.com/opencontainers/go-digest"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

type testEntry struct {
	name   string
	typ    byte
	mode   int64
	uid    int
	gid    int
	body   string
	link   string
	xattrs map[string]string
}

func dirE(name string, mode int64, uid int, xattrs ...string) testEntry {
	e := testEntry{name: name, typ: tar.TypeDir, mode: mode, uid: uid, gid: uid}
	if len(xattrs) == 2 {
		e.xattrs = map[string]string{xattrs[0]: xattrs[1]}
	}
	return e
}

func fileE(name, body string) testEntry {
	return testEntry{name: name, typ: tar.TypeReg, mode: 0644, body: body}
}

func makeTestLayer(t *testing.T, entries []testEntry) ([]byte, ocispecs.Descriptor) {
	t.Helper()
	tarBuf := &bytes.Buffer{}
	tw := tar.NewWriter(tarBuf)
	mtime := time.Unix(1700000000, 0)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: e.typ,
			Mode:     e.mode,
			Uid:      e.uid,
			Gid:      e.gid,
			Linkname: e.link,
			ModTime:  mtime,
			Format:   tar.FormatPAX,
		}
		if e.typ == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		for k, v := range e.xattrs {
			if hdr.PAXRecords == nil {
				hdr.PAXRecords = map[string]string{}
			}
			hdr.PAXRecords["SCHILY.xattr."+k] = v
		}
		require.NoError(t, tw.WriteHeader(hdr))
		if e.typ == tar.TypeReg {
			_, err := tw.Write([]byte(e.body))
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())
	gzBuf := &bytes.Buffer{}
	gw := gzip.NewWriter(gzBuf)
	_, err := gw.Write(tarBuf.Bytes())
	require.NoError(t, err)
	require.NoError(t, gw.Close())
	return gzBuf.Bytes(), ocispecs.Descriptor{
		MediaType: ocispecs.MediaTypeImageLayerGzip,
		Digest:    digest.FromBytes(gzBuf.Bytes()),
		Size:      int64(gzBuf.Len()),
		Annotations: map[string]string{
			labels.LabelUncompressed: digest.FromBytes(tarBuf.Bytes()).String(),
		},
	}
}

// detachedTestLayers covers what applying a layer without its parent has to
// get right: whiteouts, opaque directories, parent directories missing from
// the tar whose attributes come from the lower layers, a directory listed
// after its children, hardlinks, and a path through a symlink of the same
// layer (which must fall back to applying on top of the parent).
func detachedTestLayers() [][]testEntry {
	return [][]testEntry{
		{
			dirE("etc", 0750, 3),
			fileE("etc/a", "a"),
			dirE("home", 0751, 0, "user.home", "h"),
			dirE("home/user", 0700, 1000, "user.test", "1"),
			fileE("home/user/f", "f"),
			dirE("opt", 0755, 0),
			dirE("opt/data", 0750, 7, "user.x", "x"),
			dirE("del", 0711, 5),
			fileE("del/me", "me"),
			fileE("del/keep", "keep"),
			dirE("opq", 0755, 0),
			fileE("opq/x", "x"),
			fileE("opq/y", "y"),
			dirE("var", 0755, 0),
			dirE("var/lib", 0755, 0),
			dirE("var/lib/app", 0711, 33),
			{name: "lnk", typ: tar.TypeSymlink, link: "etc", mode: 0777},
		},
		{
			fileE("home/user/g", "g"),
			fileE("del/.wh.me", ""),
			dirE("opq", 0755, 0),
			fileE("opq/.wh..wh..opq", ""),
			fileE("opq/z", "z"),
			fileE("var/lib/app/new", "new"),
			fileE("opt/data/new", "new"),
			dirE("opt/data", 0700, 8),
			fileE("hl/a", "hardlinked"),
			{name: "hl/b", typ: tar.TypeLink, link: "hl/a"},
			fileE("etc/sub/file", "sub"),
		},
		{
			fileE("home/user/.wh.f", ""),
			fileE("etc/sub/file2", "sub2"),
			fileE("new/deep/dir/file", "deep"),
			fileE("del/again", "again"),
		},
		{
			// the parent path of lnk2/x is a symlink created by this layer
			{name: "lnk2", typ: tar.TypeSymlink, link: "etc", mode: 0777},
			fileE("lnk2/x", "through symlink"),
			fileE("home/user/h", "h"),
		},
	}
}

func newOverlayCacheManager(ctx context.Context, t *testing.T, parallel bool) *cmOut {
	tmpdir := t.TempDir()
	if err := overlayutils.Supported(tmpdir); err != nil {
		t.Skipf("overlayfs not supported: %v", err)
	}
	sn, err := overlay.NewSnapshotter(filepath.Join(tmpdir, "snapshots"))
	require.NoError(t, err)
	co, cleanup, err := newCacheManager(ctx, t, cmOpt{
		snapshotter:     sn,
		snapshotterName: "overlayfs",
		tmpdir:          tmpdir,
		parallelUnpack:  parallel,
	})
	require.NoError(t, err)
	t.Cleanup(cleanup)
	if parallel {
		require.NotNil(t, co.manager.(*cacheManager).unpackSem, "parallel unpack not enabled")
	}
	return co
}

// blockFetcher serves blobs from a provider, holding back the ones in block
// until release is closed.
type blockFetcher struct {
	cs      content.Provider
	block   map[digest.Digest]struct{}
	release chan struct{}
}

func (f *blockFetcher) Fetch(ctx context.Context, desc ocispecs.Descriptor) (io.ReadCloser, error) {
	if _, ok := f.block[desc.Digest]; ok {
		select {
		case <-f.release:
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
	}
	ra, err := f.cs.ReaderAt(ctx, desc)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(io.NewSectionReader(ra, 0, ra.Size())), nil
}

func lazyChain(ctx context.Context, t *testing.T, cm Manager, provider content.Provider, descs []ocispecs.Descriptor) []ImmutableRef {
	dhs := DescHandlers{}
	for _, desc := range descs {
		dhs[desc.Digest] = &DescHandler{
			Provider: func(session.Group) content.Provider { return provider },
		}
	}
	var refs []ImmutableRef
	var parent ImmutableRef
	for _, desc := range descs {
		ref, err := cm.GetByBlob(ctx, desc, parent, dhs)
		require.NoError(t, err)
		t.Cleanup(func() { ref.Release(context.WithoutCancel(ctx)) })
		refs = append(refs, ref)
		parent = ref
	}
	return refs
}

// upperDirs returns the directory of every layer of ref, topmost first.
func upperDirs(ctx context.Context, t *testing.T, ref ImmutableRef) []string {
	m, err := ref.Mount(ctx, true, nil)
	require.NoError(t, err)
	mounts, release, err := m.Mount()
	require.NoError(t, err)
	t.Cleanup(func() { release() })
	dirs, err := lowerDirs(mounts)
	require.NoError(t, err)
	return dirs
}

// treeSummary describes every file under root: type, mode, owner, device,
// content, link target, link count and xattrs (including the
// trusted.overlay ones). Directory mtimes are left out because the mtime of a
// directory that archive.Apply creates implicitly is the time of extraction.
func treeSummary(t *testing.T, root string) map[string]string {
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st := fi.Sys().(*syscall.Stat_t)
		s := fmt.Sprintf("mode=%v uid=%d gid=%d", fi.Mode(), st.Uid, st.Gid)
		switch {
		case fi.Mode().IsRegular():
			dt, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			s += fmt.Sprintf(" sha=%x nlink=%d mtime=%d", sha256.Sum256(dt), st.Nlink, fi.ModTime().Unix())
		case fi.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			s += " link=" + target
		case fi.Mode()&os.ModeCharDevice != 0:
			s += fmt.Sprintf(" rdev=%d", st.Rdev)
		}
		keys, err := sysx.LListxattr(p)
		if err != nil {
			return err
		}
		sort.Strings(keys)
		for _, k := range keys {
			v, err := sysx.LGetxattr(p, k)
			if err != nil {
				return err
			}
			s += fmt.Sprintf(" %s=%q", k, v)
		}
		out[rel] = s
		return nil
	})
	require.NoError(t, err)
	return out
}

func TestParallelUnpackMatchesSequential(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	t.Parallel()
	ctx := namespaces.WithNamespace(t.Context(), "buildkit-test")

	blobs := contentutil.NewBuffer()
	var descs []ocispecs.Descriptor
	for _, entries := range detachedTestLayers() {
		blob, desc := makeTestLayer(t, entries)
		require.NoError(t, content.WriteBlob(ctx, blobs, desc.Digest.String(), bytes.NewReader(blob), desc))
		descs = append(descs, desc)
	}

	seq := newOverlayCacheManager(ctx, t, false)
	seqRefs := lazyChain(ctx, t, seq.manager, blobs, descs)
	require.NoError(t, seqRefs[len(seqRefs)-1].Extract(ctx, nil))

	par := newOverlayCacheManager(ctx, t, true)
	// Hold back the bottom layer so that the upper layers can only be
	// extracted if they are extracted without their parents.
	fetcher := &blockFetcher{cs: blobs, block: map[digest.Digest]struct{}{descs[0].Digest: {}}, release: make(chan struct{})}
	parRefs := lazyChain(ctx, t, par.manager, contentutil.FromFetcher(fetcher), descs)
	done := make(chan error, 1)
	go func() {
		done <- parRefs[len(parRefs)-1].Extract(ctx, nil)
	}()
	require.Eventually(t, func() bool {
		var detached int
		err := par.testSnapshotter.Walk(namespaces.WithNamespace(ctx, "buildkit-test"), func(_ context.Context, info snapshots.Info) error {
			if info.Kind == snapshots.KindActive && strings.HasPrefix(info.Name, "extract-") && info.Parent == "" {
				detached++
			}
			return nil
		})
		require.NoError(t, err)
		return detached == len(descs)-1
	}, 10*time.Second, 10*time.Millisecond, "upper layers were not extracted while the bottom layer was downloading")
	close(fetcher.release)
	require.NoError(t, <-done)

	// the committed chain has the same parents
	for i := 1; i < len(parRefs); i++ {
		info, err := par.manager.(*cacheManager).Snapshotter.Stat(ctx, parRefs[i].(*immutableRef).getSnapshotID())
		require.NoError(t, err)
		require.Equal(t, parRefs[i-1].(*immutableRef).getSnapshotID(), info.Parent)
	}

	// every layer directory is identical
	seqDirs := upperDirs(ctx, t, seqRefs[len(seqRefs)-1])
	parDirs := upperDirs(ctx, t, parRefs[len(parRefs)-1])
	require.Len(t, parDirs, len(descs))
	require.Len(t, seqDirs, len(descs))
	for i := range seqDirs {
		layer := len(descs) - 1 - i
		require.Equal(t, treeSummary(t, seqDirs[i]), treeSummary(t, parDirs[i]), "layer %d", layer)
	}

	// spot-check the merged view
	merged := t.TempDir()
	m, err := parRefs[len(parRefs)-1].Mount(ctx, true, nil)
	require.NoError(t, err)
	mounts, release, err := m.Mount()
	require.NoError(t, err)
	defer release()
	require.NoError(t, mount.All(mounts, merged))
	defer mount.Unmount(merged, 0)
	for _, p := range []string{"del/me", "home/user/f", "opq/x", "opq/y"} {
		_, err := os.Lstat(filepath.Join(merged, p))
		require.True(t, os.IsNotExist(err), "%s must be deleted", p)
	}
	for _, p := range []string{"del/keep", "del/again", "opq/z", "home/user/g", "home/user/h", "etc/x", "new/deep/dir/file"} {
		_, err := os.Lstat(filepath.Join(merged, p))
		require.NoError(t, err, p)
	}
	fi, err := os.Lstat(filepath.Join(merged, "home/user"))
	require.NoError(t, err)
	require.Equal(t, os.ModeDir|0700, fi.Mode())
	require.Equal(t, uint32(1000), fi.Sys().(*syscall.Stat_t).Uid)
}

func TestScanLayerDirs(t *testing.T) {
	scan := func(entries []testEntry) *layerDirs {
		blob, _ := makeTestLayer(t, entries)
		gr, err := gzip.NewReader(bytes.NewReader(blob))
		require.NoError(t, err)
		ld, err := scanLayerDirs(gr)
		require.NoError(t, err)
		return ld
	}
	layers := detachedTestLayers()

	ld := scan(layers[0])
	require.Empty(t, ld.implicit)
	require.False(t, ld.unsafe)

	ld = scan(layers[1])
	require.Equal(t, []string{"home", "home/user", "del", "var", "var/lib", "var/lib/app", "opt", "opt/data", "hl", "etc", "etc/sub"}, ld.implicit)
	require.Contains(t, ld.listed, "opq")
	require.Contains(t, ld.listed, "opt/data")
	require.False(t, ld.unsafe)

	ld = scan(layers[3])
	require.True(t, ld.unsafe, "parent path through a symlink")

	ld = scan([]testEntry{fileE("a", "file"), fileE("a/b", "under a file")})
	require.True(t, ld.unsafe, "parent path through a file")

	ld = scan([]testEntry{dirE("a", 0755, 0), fileE("a", "replaces the dir")})
	require.True(t, ld.unsafe, "directory replaced by a file")
}

func TestParallelUnpackDiffIDMismatch(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	t.Parallel()
	ctx := namespaces.WithNamespace(t.Context(), "buildkit-test")

	blobs := contentutil.NewBuffer()
	layers := detachedTestLayers()
	var descs []ocispecs.Descriptor
	for i, entries := range layers[:2] {
		blob, desc := makeTestLayer(t, entries)
		if i == 1 {
			// claim the diffID of another layer
			_, other := makeTestLayer(t, layers[2])
			desc.Annotations[labels.LabelUncompressed] = other.Annotations[labels.LabelUncompressed]
		}
		require.NoError(t, content.WriteBlob(ctx, blobs, desc.Digest.String(), bytes.NewReader(blob), desc))
		descs = append(descs, desc)
	}

	par := newOverlayCacheManager(ctx, t, true)
	refs := lazyChain(ctx, t, par.manager, blobs, descs)
	err := refs[1].Extract(ctx, nil)
	require.ErrorContains(t, err, "failed to verify layer")

	var active []string
	err = par.testSnapshotter.Walk(ctx, func(_ context.Context, info snapshots.Info) error {
		if info.Kind == snapshots.KindActive {
			active = append(active, info.Name)
		}
		return nil
	})
	require.NoError(t, err)
	require.Empty(t, active)
}
