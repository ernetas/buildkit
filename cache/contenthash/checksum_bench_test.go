package contenthash

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/containerd/v2/plugins/snapshots/native"
	iradix "github.com/hashicorp/go-immutable-radix/v2"
	"github.com/moby/buildkit/cache"
	digest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
	proto "google.golang.org/protobuf/proto"
)

// Buf is used to prevent the benchmark from being optimized away.
var Buf []byte

func BenchmarkMarshalCacheRecords(b *testing.B) {
	v := sampleCacheRecords()
	for b.Loop() {
		var err error
		Buf, err = v.MarshalVT()
		require.NoError(b, err)
	}
}

var CacheRecordsOutput CacheRecords

func BenchmarkUnmarshalCacheRecords(b *testing.B) {
	v := sampleCacheRecords()
	buf, err := proto.Marshal(v)
	require.NoError(b, err)

	for b.Loop() {
		err := CacheRecordsOutput.UnmarshalVT(buf)
		require.NoError(b, err)
	}
}

func sampleCacheRecords() *CacheRecords {
	return &CacheRecords{
		Paths: []*CacheRecordWithPath{
			{
				Path: "/foo",
				Record: &CacheRecord{
					Digest: digest.FromString("/foo").String(),
					Type:   CacheRecordTypeDir,
				},
			},
			{
				Path: "/foo/",
				Record: &CacheRecord{
					Digest: digest.FromString("/foo/").String(),
					Type:   CacheRecordTypeDirHeader,
				},
			},
			{
				Path: "/foo/bar.txt",
				Record: &CacheRecord{
					Digest: digest.FromString("/foo/bar.txt").String(),
					Type:   CacheRecordTypeFile,
				},
			},
			{
				Path: "/foo/link",
				Record: &CacheRecord{
					Digest:   digest.FromString("/foo/link").String(),
					Type:     CacheRecordTypeSymlink,
					Linkname: "/foo/bar.txt",
				},
			},
		},
	}
}

// BenchmarkChecksumCold measures the first checksum of a directory in a new
// ref, when no digest is known yet. The page cache is warm.
func BenchmarkChecksumCold(b *testing.B) {
	for _, tc := range []struct {
		name  string
		files int
		size  func(r *rand.Rand) int
	}{
		// node_modules-like: many small files, a few larger ones.
		{"small-files", 20000, func(r *rand.Rand) int {
			switch n := r.IntN(100); {
			case n < 85:
				return r.IntN(4 << 10)
			case n < 98:
				return 4<<10 + r.IntN(60<<10)
			default:
				return 64<<10 + r.IntN(448<<10)
			}
		}},
		// SDK-like: fewer, larger files.
		{"mixed", 2000, func(r *rand.Rand) int {
			switch n := r.IntN(100); {
			case n < 60:
				return r.IntN(16 << 10)
			case n < 95:
				return 16<<10 + r.IntN(240<<10)
			default:
				return 1<<20 + r.IntN(3<<20)
			}
		}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			var total int64
			ref := benchRef(b, func(root string) error {
				r := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // deterministic test data
				buf := make([]byte, 4<<20)
				for i := range buf {
					buf[i] = byte(r.Uint32())
				}
				for i := range tc.files {
					dir := filepath.Join(root, "tree", fmt.Sprintf("d%02d", i%50), fmt.Sprintf("s%d", i%7))
					if err := os.MkdirAll(dir, 0755); err != nil {
						return err
					}
					n := tc.size(r)
					total += int64(n)
					off := r.IntN(len(buf) - n)
					if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%05d", i)), buf[off:off+n], 0644); err != nil {
						return err
					}
				}
				return nil
			})
			b.SetBytes(total)
			b.ResetTimer()
			for b.Loop() {
				cc := benchCacheContext(ref)
				_, err := cc.Checksum(b.Context(), ref, "/tree", ChecksumOpts{}, nil)
				require.NoError(b, err)
			}
		})
	}
}

// BenchmarkChecksumSubdir measures the first checksum of a small directory
// next to a large one, like COPY --from=stage /app/dist from a stage whose
// rootfs or /app also holds node_modules. entries/op is the number of
// filesystem entries scanned.
func BenchmarkChecksumSubdir(b *testing.B) {
	ref := benchRef(b, func(root string) error {
		for i := range 20000 {
			dir := filepath.Join(root, "app", "node_modules", fmt.Sprintf("m%03d", i%200))
			if err := os.MkdirAll(dir, 0755); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%05d.js", i)), []byte("x"), 0644); err != nil {
				return err
			}
		}
		if err := os.MkdirAll(filepath.Join(root, "app", "dist"), 0755); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(root, "app", "dist", "main.js"), []byte("main"), 0644)
	})
	for _, tc := range []struct {
		name string
		path string
		opts ChecksumOpts
	}{
		{"path", "/app/dist", ChecksumOpts{}},
		{"wildcard", "/app/dist/*.js", ChecksumOpts{Wildcard: true}},
		{"exclude", "/app/dist", ChecksumOpts{ExcludePatterns: []string{"*.map"}}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			scanCounterEnable = true
			defer func() { scanCounterEnable = false }()
			start := scanCounter.Load()
			for b.Loop() {
				cc := benchCacheContext(ref)
				_, err := cc.Checksum(b.Context(), ref, tc.path, tc.opts, nil)
				require.NoError(b, err)
			}
			b.ReportMetric(float64(scanCounter.Load()-start)/float64(b.N), "entries/op")
		})
	}
}

func benchRef(b *testing.B, fn func(root string) error) cache.ImmutableRef {
	tmpdir := b.TempDir()
	snapshotter, err := native.NewSnapshotter(filepath.Join(tmpdir, "snapshots"))
	require.NoError(b, err)
	cm, cleanup := setupCacheManager(b, tmpdir, "native", snapshotter)
	b.Cleanup(cleanup)

	ref := createRefFunc(b, cm, fn)
	b.Cleanup(func() { ref.Release(b.Context()) })
	return ref
}

// benchCacheContext returns an empty cache context for ref that does not
// persist its records, so every iteration starts cold.
func benchCacheContext(ref cache.ImmutableRef) *cacheContext {
	return &cacheContext{
		md:       cacheMetadata{noSaveMetadata{ref}},
		tree:     iradix.New[*CacheRecord](),
		dirtyMap: map[string]struct{}{},
		linkMap:  map[string][][]byte{},
	}
}

type noSaveMetadata struct {
	cache.RefMetadata
}

func (noSaveMetadata) SetExternal(string, []byte) error {
	return nil
}
