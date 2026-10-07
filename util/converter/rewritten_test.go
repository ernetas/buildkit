package converter

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"math/rand"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/leases"
	ctdmetadata "github.com/containerd/containerd/v2/core/metadata"
	"github.com/containerd/containerd/v2/pkg/labels"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/plugins/content/local"
	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/buildkit/util/compression"
	digest "github.com/opencontainers/go-digest"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

type testStore struct {
	content.Store
	db     *ctdmetadata.DB
	leases leases.Manager
}

// newTestStore returns a containerd metadata content store, which keeps labels
// and garbage collects the way the worker's store does.
func newTestStore(t testing.TB) (context.Context, *testStore) {
	tmpdir := t.TempDir()
	store, err := local.NewStore(filepath.Join(tmpdir, "content"))
	require.NoError(t, err)
	db, err := bolt.Open(filepath.Join(tmpdir, "meta.db"), 0644, nil)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	mdb := ctdmetadata.NewDB(db, store, nil)
	ctx := namespaces.WithNamespace(t.Context(), "buildkit-test")
	require.NoError(t, mdb.Init(ctx))
	return ctx, &testStore{Store: mdb.ContentStore(), db: mdb, leases: ctdmetadata.NewLeaseManager(mdb)}
}

// countingStore counts the reads of one blob.
type countingStore struct {
	content.Store
	dgst  digest.Digest
	reads atomic.Int64
}

func (s *countingStore) ReaderAt(ctx context.Context, desc ocispecs.Descriptor) (content.ReaderAt, error) {
	if desc.Digest == s.dgst {
		s.reads.Add(1)
	}
	return s.Store.ReaderAt(ctx, desc)
}

// testLayer returns a gzip layer of files modified now, after any test epoch.
func testLayer(t testing.TB, size int) ([]byte, digest.Digest) {
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	rnd := rand.New(rand.NewSource(1)) //nolint:gosec // deterministic test data
	now := time.Now()
	for i := 0; size > 0; i++ {
		n := min(size, 1<<20)
		size -= n
		data := make([]byte, n)
		for j := range data {
			data[j] = "abcdefghij"[rnd.Intn(10)] // compressible
		}
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name: fmt.Sprintf("file%d", i), Mode: 0644, Size: int64(n),
			ModTime: now, AccessTime: now, ChangeTime: now, Format: tar.FormatPAX,
		}))
		_, err := tw.Write(data)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	diffID := digest.FromBytes(tarBuf.Bytes())
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	_, err := gw.Write(tarBuf.Bytes())
	require.NoError(t, err)
	require.NoError(t, gw.Close())
	return gzBuf.Bytes(), diffID
}

func writeLayer(ctx context.Context, t testing.TB, cs content.Store, blob []byte, diffID digest.Digest) ocispecs.Descriptor {
	desc := ocispecs.Descriptor{
		MediaType:   ocispecs.MediaTypeImageLayerGzip,
		Digest:      digest.FromBytes(blob),
		Size:        int64(len(blob)),
		Annotations: map[string]string{labels.LabelUncompressed: diffID.String()},
	}
	require.NoError(t, content.WriteBlob(ctx, cs, "layer", bytes.NewReader(blob), desc,
		content.WithLabels(map[string]string{labels.LabelUncompressed: diffID.String()})))
	return desc
}

func rewrite(ctx context.Context, t testing.TB, cs content.Store, desc ocispecs.Descriptor, comp compression.Config, epoch time.Time, immDiffIDs map[digest.Digest]struct{}) ocispecs.Descriptor {
	fn, err := NewWithRewriteTimestamp(ctx, cs, desc, comp, &epoch, immDiffIDs)
	require.NoError(t, err)
	require.NotNil(t, fn)
	out, err := fn(ctx, cs, desc)
	require.NoError(t, err)
	require.NotNil(t, out)
	return *out
}

// freshRewrite converts in a new store, as an export without any earlier
// result would.
func freshRewrite(t testing.TB, blob []byte, diffID digest.Digest, comp compression.Config, epoch time.Time) ocispecs.Descriptor {
	ctx, cs := newTestStore(t)
	desc := writeLayer(ctx, t, cs, blob, diffID)
	return rewrite(ctx, t, cs, desc, comp, epoch, nil)
}

func rewrittenLabels(ctx context.Context, t testing.TB, cs content.Store, dgst digest.Digest) map[string]string {
	info, err := cs.Info(ctx, dgst)
	require.NoError(t, err)
	out := map[string]string{}
	for k, v := range info.Labels {
		if strings.HasPrefix(k, rewrittenLabelPrefix) {
			out[k] = v
		}
	}
	return out
}

func TestRewriteTimestampReusesResult(t *testing.T) {
	blob, diffID := testLayer(t, 3<<20)
	epoch := time.Unix(1700000000, 0)
	for _, comp := range []compression.Config{
		compression.New(compression.Uncompressed),
		compression.New(compression.Gzip),
		compression.New(compression.Gzip).SetLevel(9),
		compression.New(compression.Zstd),
		compression.New(compression.Zstd).SetLevel(9),
	} {
		key, _ := comp.OutputKey()
		t.Run(key, func(t *testing.T) {
			ctx, ts := newTestStore(t)
			desc := writeLayer(ctx, t, ts, blob, diffID)
			cs := &countingStore{Store: ts, dgst: desc.Digest}

			first := rewrite(ctx, t, cs, desc, comp, epoch, nil)
			require.NotEqual(t, desc.Digest, first.Digest)
			require.Positive(t, cs.reads.Load())

			cs.reads.Store(0)
			second := rewrite(ctx, t, cs, desc, comp, epoch, nil)
			require.Equal(t, first, second)
			require.Zero(t, cs.reads.Load(), "the source must not be read again")

			// what an export with nothing to reuse returns
			require.Equal(t, freshRewrite(t, blob, diffID, comp, epoch), second)
		})
	}
}

func TestRewriteTimestampKeyedByEpochAndCompression(t *testing.T) {
	blob, diffID := testLayer(t, 1<<20)
	e1, e2 := time.Unix(1700000000, 0), time.Unix(1600000000, 0)
	gz, gz1 := compression.New(compression.Gzip), compression.New(compression.Gzip).SetLevel(1)
	zst, zst1 := compression.New(compression.Zstd), compression.New(compression.Zstd).SetLevel(1)

	ctx, cs := newTestStore(t)
	desc := writeLayer(ctx, t, cs, blob, diffID)
	seen := map[digest.Digest]string{}
	// Every result must match a fresh conversion with the same settings, even
	// with results for other settings recorded on the same source.
	for i, tc := range []struct {
		comp  compression.Config
		epoch time.Time
	}{
		{gz, e1}, {gz, e2}, {gz1, e1}, {zst, e1}, {zst1, e1}, {zst, e2},
		{gz, e1}, {gz1, e1}, {zst1, e1},
	} {
		key, _ := tc.comp.OutputKey()
		name := fmt.Sprintf("%d-%s-%d", i, key, tc.epoch.Unix())
		got := rewrite(ctx, t, cs, desc, tc.comp, tc.epoch, nil)
		require.Equal(t, freshRewrite(t, blob, diffID, tc.comp, tc.epoch), got, name)
		if prev, ok := seen[got.Digest]; ok {
			require.Equal(t, prev, fmt.Sprintf("%s-%d", key, tc.epoch.Unix()), "%s reused the result of %s", name, prev)
		}
		seen[got.Digest] = fmt.Sprintf("%s-%d", key, tc.epoch.Unix())
	}
	require.Len(t, seen, 6)
	require.Len(t, rewrittenLabels(ctx, t, cs, desc.Digest), maxRewrittenVariants)
}

func TestRewriteTimestampKeepsNewestEpochs(t *testing.T) {
	blob, diffID := testLayer(t, 64<<10)
	ctx, cs := newTestStore(t)
	desc := writeLayer(ctx, t, cs, blob, diffID)
	comp := compression.New(compression.Gzip)
	for i := range 2 * maxRewrittenVariants {
		rewrite(ctx, t, cs, desc, comp, time.Unix(1600000000+int64(i), 0), nil)
	}
	got := rewrittenLabels(ctx, t, cs, desc.Digest)
	require.Len(t, got, maxRewrittenVariants)
	for i := maxRewrittenVariants; i < 2*maxRewrittenVariants; i++ {
		key, _ := comp.OutputKey()
		require.Contains(t, got, rewrittenBlobLabel(time.Unix(1600000000+int64(i), 0), key))
	}
}

func TestRewriteTimestampMissingResult(t *testing.T) {
	blob, diffID := testLayer(t, 64<<10)
	epoch := time.Unix(1700000000, 0)
	comp := compression.New(compression.Zstd)
	ctx, ts := newTestStore(t)
	desc := writeLayer(ctx, t, ts, blob, diffID)
	first := rewrite(ctx, t, ts, desc, comp, epoch, nil)

	// point the record at a blob that is gone
	key, _ := comp.OutputKey()
	label := rewrittenBlobLabel(epoch, key)
	_, err := ts.Update(ctx, content.Info{Digest: desc.Digest, Labels: map[string]string{label: digest.FromString("gone").String()}}, "labels."+label)
	require.NoError(t, err)

	cs := &countingStore{Store: ts, dgst: desc.Digest}
	require.Equal(t, first, rewrite(ctx, t, cs, desc, comp, epoch, nil))
	require.Positive(t, cs.reads.Load(), "must convert again")
	require.Equal(t, first.Digest.String(), rewrittenLabels(ctx, t, ts, desc.Digest)[label])
}

func TestRewriteTimestampImmutableDiffID(t *testing.T) {
	blob, diffID := testLayer(t, 64<<10)
	epoch := time.Unix(1700000000, 0)
	comp := compression.New(compression.Gzip)
	ctx, cs := newTestStore(t)
	desc := writeLayer(ctx, t, cs, blob, diffID)
	rewrite(ctx, t, cs, desc, comp, epoch, nil)

	// a recorded result must not override the immutable base layer check
	desc.Annotations = nil
	got := rewrite(ctx, t, cs, desc, comp, epoch, map[digest.Digest]struct{}{diffID: {}})
	require.Equal(t, desc, got)
}

func TestRewriteTimestampResultLivesWithSource(t *testing.T) {
	blob, diffID := testLayer(t, 64<<10)
	epoch := time.Unix(1700000000, 0)
	ctx, cs := newTestStore(t)

	// the source is held by a lease, like a cache record's blob
	srcLease, err := cs.leases.Create(ctx, leases.WithRandomID())
	require.NoError(t, err)
	desc := writeLayer(leases.WithLease(ctx, srcLease.ID), t, cs, blob, diffID)

	// the export converts under a temporary lease that it then deletes
	expLease, err := cs.leases.Create(ctx, leases.WithRandomID())
	require.NoError(t, err)
	out := rewrite(leases.WithLease(ctx, expLease.ID), t, cs, desc, compression.New(compression.Gzip), epoch, nil)
	require.NoError(t, cs.leases.Delete(ctx, expLease))

	_, err = cs.db.GarbageCollect(ctx)
	require.NoError(t, err)
	_, err = cs.Info(ctx, out.Digest)
	require.NoError(t, err, "the rewritten blob must live as long as its source")

	require.NoError(t, cs.leases.Delete(ctx, srcLease))
	_, err = cs.db.GarbageCollect(ctx)
	require.NoError(t, err)
	_, err = cs.Info(ctx, desc.Digest)
	require.ErrorIs(t, err, cerrdefs.ErrNotFound)
	_, err = cs.Info(ctx, out.Digest)
	require.ErrorIs(t, err, cerrdefs.ErrNotFound, "the rewritten blob must not outlive its source")
}

func TestRewriteTimestampReuseIsLeased(t *testing.T) {
	blob, diffID := testLayer(t, 64<<10)
	epoch := time.Unix(1700000000, 0)
	comp := compression.New(compression.Gzip)
	ctx, cs := newTestStore(t)

	// A flat lease, like the one holding a cache record's blob, does not
	// keep what the blob's labels reference.
	srcLease, err := cs.leases.Create(ctx, leases.WithRandomID(), leases.WithLabel("containerd.io/gc.flat", time.Now().UTC().Format(time.RFC3339Nano)))
	require.NoError(t, err)
	desc := writeLayer(leases.WithLease(ctx, srcLease.ID), t, cs, blob, diffID)

	exp1, err := cs.leases.Create(ctx, leases.WithRandomID())
	require.NoError(t, err)
	first := rewrite(leases.WithLease(ctx, exp1.ID), t, cs, desc, comp, epoch, nil)

	// A second export reuses the blob and must hold it until it is done,
	// as it would hold a blob it wrote.
	exp2, err := cs.leases.Create(ctx, leases.WithRandomID())
	require.NoError(t, err)
	cnt := &countingStore{Store: cs, dgst: desc.Digest}
	second := rewrite(leases.WithLease(ctx, exp2.ID), t, cnt, desc, comp, epoch, nil)
	require.Equal(t, first, second)
	require.Zero(t, cnt.reads.Load())

	require.NoError(t, cs.leases.Delete(ctx, exp1))
	_, err = cs.db.GarbageCollect(ctx)
	require.NoError(t, err)
	_, err = cs.Info(ctx, second.Digest)
	require.NoError(t, err, "the reused blob must be held by the export's lease")

	require.NoError(t, cs.leases.Delete(ctx, exp2))
	_, err = cs.db.GarbageCollect(ctx)
	require.NoError(t, err)
	_, err = cs.Info(ctx, second.Digest)
	require.ErrorIs(t, err, cerrdefs.ErrNotFound)

	// The record now names a missing blob: the next export converts again.
	cnt.reads.Store(0)
	require.Equal(t, first, rewrite(ctx, t, cnt, desc, comp, epoch, nil))
	require.Positive(t, cnt.reads.Load())
}

func TestRewrittenBlobLabel(t *testing.T) {
	require.Equal(t, "containerd.io/gc.ref.content.buildkit/rewritten/v1/1700000000/zstd-3-sequential",
		rewrittenBlobLabel(time.Unix(1700000000, 0), "zstd-3-sequential"))
	require.Equal(t, int64(1700000000), rewrittenLabelEpoch(rewrittenBlobLabel(time.Unix(1700000000, 5), "gzip-default")))
	require.NotEqual(t, rewrittenBlobLabel(time.Unix(1700000000, 0), "gzip-default"), rewrittenBlobLabel(time.Unix(1700000000, 5), "gzip-default"))
}

// BenchmarkRewriteTimestampRepeat converts a layer that an earlier export
// already converted with the same settings.
func BenchmarkRewriteTimestampRepeat(b *testing.B) {
	blob, diffID := testLayer(b, 32<<20)
	epoch := time.Unix(1700000000, 0)
	for _, comp := range []compression.Config{compression.New(compression.Gzip), compression.New(compression.Zstd)} {
		b.Run(comp.Type.String(), func(b *testing.B) {
			ctx, cs := newTestStore(b)
			desc := writeLayer(ctx, b, cs, blob, diffID)
			rewrite(ctx, b, cs, desc, comp, epoch, nil)
			b.SetBytes(int64(len(blob)))
			b.ResetTimer()
			for b.Loop() {
				rewrite(ctx, b, cs, desc, comp, epoch, nil)
			}
		})
	}
}
