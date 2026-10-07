package cacheimport

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	cacheimporttypes "github.com/moby/buildkit/cache/remotecache/v1/types"
	"github.com/moby/buildkit/solver"
	digest "github.com/opencontainers/go-digest"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

// testStep is one cache record on top of a shared "base" root record, with a
// result made of blobs and created at createdAt.
type testStep struct {
	name      string
	parent    string // another step, or "" for the base
	blobs     []string
	createdAt time.Time
}

func buildTestConfig(t testing.TB, steps ...testStep) (*cacheimporttypes.CacheConfig, DescriptorProvider) {
	t.Helper()
	cc := NewCacheChains()
	base, _, err := cc.Add(outputKey(dgst("base"), 0), nil, nil)
	require.NoError(t, err)
	recs := map[string]solver.CacheExporterRecord{"": base}
	for _, s := range steps {
		r := &solver.Remote{}
		for _, b := range s.blobs {
			r.Descriptors = append(r.Descriptors, ocispecs.Descriptor{Digest: dgst(b), Size: 1, MediaType: ocispecs.MediaTypeImageLayerGzip})
		}
		parent, ok := recs[s.parent]
		require.True(t, ok, s.parent)
		rec, _, err := cc.Add(outputKey(dgst(s.name), 0), [][]solver.CacheLink{{{Src: parent}}}, []solver.CacheExportResult{{CreatedAt: s.createdAt, Result: r}})
		require.NoError(t, err)
		recs[s.name] = rec
	}
	cfg, descs, err := cc.Marshal(t.Context())
	require.NoError(t, err)
	return cfg, descs
}

// recordResults maps the digest of every record with a result to the blob
// chain of that result.
func recordResults(cfg *cacheimporttypes.CacheConfig) map[digest.Digest][]digest.Digest {
	out := map[digest.Digest][]digest.Digest{}
	for _, rec := range cfg.Records {
		for _, r := range rec.Results {
			out[rec.Digest] = layerToBlobs(cfg.Layers, r.LayerIndex)
		}
	}
	return out
}

func layerToBlobs(layers []cacheimporttypes.CacheLayer, idx int) []digest.Digest {
	var blobs []digest.Digest
	for idx != -1 {
		blobs = append([]digest.Digest{layers[idx].Blob}, blobs...)
		idx = layers[idx].ParentIndex
	}
	return blobs
}

func configSize(t *testing.T, cfg *cacheimporttypes.CacheConfig) int {
	dt, err := json.Marshal(cfg)
	require.NoError(t, err)
	return len(dt)
}

// BenchmarkMerge measures the cost Merge adds to an export: a previous config
// of 2000 single-step records, each created at a different time, merged into
// a current config of 50 under a budget that keeps about half of them.
func BenchmarkMerge(b *testing.B) {
	now := time.Now()
	steps := func(prefix string, n int) (out []testStep) {
		for i := range n {
			name := fmt.Sprintf("%s%d", prefix, i)
			out = append(out, testStep{name: name, blobs: []string{"deps", name}, createdAt: now.Add(-time.Duration(i) * time.Minute)})
		}
		return out
	}
	prev, prevDescs := buildTestConfig(b, steps("prev", 2000)...)
	cur, curDescs := buildTestConfig(b, steps("cur", 50)...)
	all, _, _, err := Merge(b.Context(), cur, curDescs, prev, prevDescs, MergeOpt{})
	require.NoError(b, err)
	dt, err := json.Marshal(all)
	require.NoError(b, err)
	opt := MergeOpt{MaxConfigSize: len(dt) / 2}

	var stats MergeStats
	b.ReportAllocs()
	for b.Loop() {
		_, _, stats, err = Merge(b.Context(), cur, curDescs, prev, prevDescs, opt)
		if err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(stats.AddedRecords), "added")
	b.ReportMetric(float64(stats.Size), "config-bytes")
}

func TestMerge(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key := func(name string) digest.Digest { return outputKey(dgst(name), 0) }

	// The previous export came from another target: it shares "deps" with the
	// current build, and has its own "a-compile" stages.
	prev, prevDescs := buildTestConfig(t,
		testStep{name: "deps", blobs: []string{"deps-old"}, createdAt: now.Add(-3 * time.Hour)},
		testStep{name: "a-old", parent: "deps", blobs: []string{"deps-old", "a-old"}, createdAt: now.Add(-48 * time.Hour)},
		testStep{name: "a-compile", parent: "deps", blobs: []string{"deps-old", "a-compile"}, createdAt: now.Add(-2 * time.Hour)},
	)
	cur, curDescs := buildTestConfig(t,
		testStep{name: "deps", blobs: []string{"deps-new"}, createdAt: now.Add(-time.Hour)},
		testStep{name: "b-compile", parent: "deps", blobs: []string{"deps-new", "b-compile"}, createdAt: now.Add(-time.Hour)},
	)

	t.Run("union", func(t *testing.T) {
		merged, descs, stats, err := Merge(t.Context(), cur, curDescs, prev, prevDescs, MergeOpt{})
		require.NoError(t, err)
		require.Equal(t, 2, stats.AddedRecords)
		require.Equal(t, configSize(t, merged), stats.Size)

		res := recordResults(merged)
		require.Equal(t, []digest.Digest{dgst("deps-new")}, res[key("deps")], "the newer result of a shared record wins")
		require.Equal(t, []digest.Digest{dgst("deps-new"), dgst("b-compile")}, res[key("b-compile")])
		require.Equal(t, []digest.Digest{dgst("deps-old"), dgst("a-compile")}, res[key("a-compile")])
		require.Equal(t, []digest.Digest{dgst("deps-old"), dgst("a-old")}, res[key("a-old")])
		for _, l := range merged.Layers {
			require.Contains(t, descs, l.Blob)
		}

		// The result is a plain v1 config that any importer can parse, and
		// merging it again changes nothing.
		require.NoError(t, ParseConfig(*merged, descs, NewCacheChains()))
		again, _, stats, err := Merge(t.Context(), merged, descs, prev, prevDescs, MergeOpt{})
		require.NoError(t, err)
		require.Equal(t, 0, stats.AddedRecords)
		require.Equal(t, merged, again)
	})

	t.Run("max age", func(t *testing.T) {
		merged, _, stats, err := Merge(t.Context(), cur, curDescs, prev, prevDescs, MergeOpt{MaxAge: 24 * time.Hour, Now: now})
		require.NoError(t, err)
		require.Equal(t, 1, stats.AddedRecords)
		res := recordResults(merged)
		require.Contains(t, res, key("a-compile"))
		require.NotContains(t, res, key("a-old"))
	})

	t.Run("size budget drops oldest first", func(t *testing.T) {
		all, _, _, err := Merge(t.Context(), cur, curDescs, prev, prevDescs, MergeOpt{})
		require.NoError(t, err)
		merged, _, stats, err := Merge(t.Context(), cur, curDescs, prev, prevDescs, MergeOpt{MaxConfigSize: configSize(t, all) - 1})
		require.NoError(t, err)
		require.Equal(t, 1, stats.AddedRecords)
		require.LessOrEqual(t, stats.Size, configSize(t, all)-1)
		res := recordResults(merged)
		require.Contains(t, res, key("a-compile"))
		require.NotContains(t, res, key("a-old"))
	})

	t.Run("current config over budget", func(t *testing.T) {
		merged, descs, stats, err := Merge(t.Context(), cur, curDescs, prev, prevDescs, MergeOpt{MaxConfigSize: 1})
		require.NoError(t, err)
		require.Equal(t, 0, stats.AddedRecords)
		require.Same(t, cur, merged)
		require.Equal(t, curDescs, descs)
	})

	t.Run("dependencies of kept records are kept", func(t *testing.T) {
		// "a-compile" is newer than the cutoff but depends on "deps", whose
		// only result in this previous config is older than the cutoff.
		prev, prevDescs := buildTestConfig(t,
			testStep{name: "deps", blobs: []string{"deps-old"}, createdAt: now.Add(-72 * time.Hour)},
			testStep{name: "a-compile", parent: "deps", blobs: []string{"deps-old", "a-compile"}, createdAt: now.Add(-2 * time.Hour)},
		)
		cur, curDescs := buildTestConfig(t,
			testStep{name: "other", blobs: []string{"other"}, createdAt: now},
		)
		merged, _, stats, err := Merge(t.Context(), cur, curDescs, prev, prevDescs, MergeOpt{MaxAge: 24 * time.Hour, Now: now})
		require.NoError(t, err)
		require.Equal(t, 2, stats.AddedRecords)
		res := recordResults(merged)
		require.Contains(t, res, key("a-compile"))
		require.Contains(t, res, key("deps"))
	})
}
