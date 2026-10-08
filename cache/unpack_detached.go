package cache

import (
	"context"
	"fmt"

	"github.com/containerd/containerd/v2/core/leases"
	"github.com/containerd/containerd/v2/core/snapshots"
	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/buildkit/identity"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/util/progress"
	"github.com/moby/buildkit/util/tracing"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// maxParallelUnpack bounds the layers that are extracted at the same time.
const maxParallelUnpack = 4

// detachedLayer is a layer that has been extracted into an active snapshot
// without parent and still has to be committed onto its parent.
type detachedLayer struct {
	key    string
	upper  string
	dirs   *layerDirs
	digest string
}

// applyDetached extracts the layer into a new active snapshot that has no
// parent. On error, the returned detachedLayer, if any, names the active
// snapshot that the caller has to remove.
func (sr *immutableRef) applyDetached(ctx context.Context, desc ocispecs.Descriptor, pg progress.Controller) (_ *detachedLayer, rerr error) {
	if err := sr.cm.unpackSem.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	defer sr.cm.unpackSem.Release(1)

	if pg != nil {
		_, stopProgress := pg.Start(ctx)
		defer stopProgress(rerr)
		statusDone := pg.Status("extracting "+desc.Digest.String(), "extracting")
		defer statusDone()
	}
	sp, ctx := tracing.StartSpan(ctx, "extract", trace.WithAttributes(
		attribute.String("digest", desc.Digest.String()),
		attribute.Int("size", int(desc.Size)),
		attribute.Bool("detached", true),
	))
	defer sp.End()

	dl := &detachedLayer{
		key:    fmt.Sprintf("extract-%s %s", identity.NewID(), sr.getChainID()),
		digest: desc.Digest.String(),
	}
	if err := sr.cm.Snapshotter.Prepare(ctx, dl.key, ""); err != nil {
		return nil, err
	}
	mountable, err := sr.cm.Snapshotter.Mounts(ctx, dl.key)
	if err != nil {
		return dl, err
	}
	mounts, unmount, err := mountable.Mount()
	if err != nil {
		return dl, err
	}
	defer unmount()

	diffID, dirs, err := applyToUpper(ctx, sr.cm.ContentStore, desc, mounts)
	if err != nil {
		return dl, err
	}
	if diffID != sr.getDiffID() {
		return dl, errors.Errorf("failed to verify layer %s: expected diffID %s, got %s", desc.Digest, sr.getDiffID(), diffID)
	}
	dl.upper = mounts[0].Source
	dl.dirs = dirs
	return dl, nil
}

// commitDetached commits a detached layer onto its now extracted parent. It
// returns false without error if the layer has to be applied on top of the
// parent instead.
func (sr *immutableRef) commitDetached(ctx context.Context, dl *detachedLayer, parentID string, s session.Group) (bool, error) {
	if dl.dirs.unsafe {
		return false, nil
	}
	if len(dl.dirs.implicit) > 0 {
		// the parent's own read-only view lists the directories of all
		// layers below this one
		mountable, err := sr.layerParent.Mount(ctx, true, s)
		if err != nil {
			return false, err
		}
		mounts, unmount, err := mountable.Mount()
		if err != nil {
			return false, err
		}
		defer unmount()
		lowers, err := lowerDirs(mounts)
		if err != nil {
			return false, err
		}
		if err := fixupImplicitDirs(dl.upper, lowers, dl.dirs); err != nil {
			return false, errors.Wrapf(err, "failed to copy parent directory attributes for layer %s", dl.digest)
		}
	}
	if err := sr.cm.Snapshotter.Commit(ctx, sr.getSnapshotID(), dl.key, snapshots.WithParent(parentID)); err != nil {
		if errors.Is(err, cerrdefs.ErrAlreadyExists) {
			// leave the duplicate to the regular path, which handles it
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// releaseSnapshot drops a snapshot that this extraction created from the
// extraction lease, so that the next garbage collection removes it.
func (sr *immutableRef) releaseSnapshot(ctx context.Context, key string) error {
	leaseID, ok := leases.FromContext(ctx)
	if !ok {
		return nil
	}
	if err := sr.cm.LeaseManager.DeleteResource(ctx, leases.Lease{ID: leaseID}, leases.Resource{
		ID:   key,
		Type: "snapshots/" + sr.cm.Snapshotter.Name(),
	}); err != nil && !cerrdefs.IsNotFound(err) {
		return errors.Wrapf(err, "failed to delete snapshot %s from lease %s", key, leaseID)
	}
	return nil
}
