package cache

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"path/filepath"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/pkg/labels"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/plugins/snapshots/native"
	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/util/compression"
	"github.com/moby/buildkit/util/converter"
	"github.com/moby/buildkit/util/leaseutil"
	digest "github.com/opencontainers/go-digest"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

// TestRewrittenTimestampBlobLifecycle checks that a blob with rewritten
// timestamps, recorded on a ref's blob by an export, counts toward the ref's
// size and is kept and pruned together with the ref.
func TestRewrittenTimestampBlobLifecycle(t *testing.T) {
	t.Parallel()
	ctx := namespaces.WithNamespace(t.Context(), "buildkit-test")

	snapshotter, err := native.NewSnapshotter(filepath.Join(t.TempDir(), "snapshots"))
	require.NoError(t, err)
	co, cleanup, err := newCacheManager(ctx, t, cmOpt{
		snapshotter:     snapshotter,
		snapshotterName: "native",
	})
	require.NoError(t, err)
	t.Cleanup(cleanup)

	// a layer with a file modified after the epoch
	var tarBuf, gzBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "foo", Mode: 0644, Size: 3, ModTime: time.Now()}))
	_, err = tw.Write([]byte("bar"))
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	gw := gzip.NewWriter(&gzBuf)
	_, err = gw.Write(tarBuf.Bytes())
	require.NoError(t, err)
	require.NoError(t, gw.Close())
	desc := ocispecs.Descriptor{
		MediaType:   ocispecs.MediaTypeImageLayerGzip,
		Digest:      digest.FromBytes(gzBuf.Bytes()),
		Size:        int64(gzBuf.Len()),
		Annotations: map[string]string{labels.LabelUncompressed: digest.FromBytes(tarBuf.Bytes()).String()},
	}
	require.NoError(t, content.WriteBlob(ctx, co.cs, "layer", bytes.NewReader(gzBuf.Bytes()), desc))

	ref, err := co.manager.GetByBlob(ctx, desc, nil)
	require.NoError(t, err)
	sr := ref.(*immutableRef)
	// GetRemotes links every blob it creates to the ref's variants lease,
	// whose blobs keep what their labels reference.
	require.NoError(t, sr.linkBlob(ctx, desc))
	size, err := sr.size(ctx)
	require.NoError(t, err)
	require.Equal(t, desc.Size, size)

	// the image exporter rewrites under a temporary lease
	epoch := time.Unix(1700000000, 0)
	exportCtx, done, err := leaseutil.WithLease(ctx, co.lm, leaseutil.MakeTemporary)
	require.NoError(t, err)
	convert, err := converter.NewWithRewriteTimestamp(exportCtx, co.cs, desc, compression.New(compression.Gzip), &epoch, nil)
	require.NoError(t, err)
	rewritten, err := convert(exportCtx, co.cs, desc)
	require.NoError(t, err)
	require.NoError(t, done(exportCtx))
	require.NotEqual(t, desc.Digest, rewritten.Digest)

	sr.mu.Lock()
	require.NoError(t, sr.queueSize(sizeUnknown))
	require.NoError(t, sr.commitMetadata())
	sr.mu.Unlock()
	size, err = sr.size(ctx)
	require.NoError(t, err)
	require.Equal(t, desc.Size+rewritten.Size, size)

	// garbage collection keeps it while the ref exists
	require.NoError(t, co.manager.Prune(ctx, nil, client.PruneInfo{All: true}))
	_, err = co.cs.Info(ctx, rewritten.Digest)
	require.NoError(t, err)

	require.NoError(t, ref.Release(ctx))
	require.NoError(t, co.manager.Prune(ctx, nil, client.PruneInfo{All: true}))
	_, err = co.cs.Info(ctx, rewritten.Digest)
	require.ErrorIs(t, err, cerrdefs.ErrNotFound)
	checkNumBlobs(ctx, t, co.cs, 0)
}
