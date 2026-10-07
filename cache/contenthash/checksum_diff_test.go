package contenthash

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/containerd/containerd/v2/plugins/snapshots/native"
	iradix "github.com/hashicorp/go-immutable-radix/v2"
	"github.com/moby/buildkit/cache"
	digest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
)

// TestChecksumDifferential checks that the digests do not depend on how
// checksum requests are scheduled: how many files are hashed in parallel,
// which parts of the tree were scanned before, and in which order paths are
// requested. For each randomly generated tree, every query is first answered
// by a reference context that hashes serially and has scanned the whole tree
// up front. The same queries are then answered by contexts that start empty,
// hash in parallel, share their state across queries in random orders, run
// concurrently, and are persisted and loaded again.
func TestChecksumDifferential(t *testing.T) {
	seeds := 24
	if testing.Short() {
		seeds = 6
	}
	for seed := range seeds {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			testChecksumDifferential(t, uint64(seed))
		})
	}
}

func testChecksumDifferential(t *testing.T, seed uint64) {
	tmpdir := t.TempDir()
	snapshotter, err := native.NewSnapshotter(filepath.Join(tmpdir, "snapshots"))
	require.NoError(t, err)
	cm, cleanup := setupCacheManager(t, tmpdir, "native", snapshotter)
	t.Cleanup(cleanup)

	r := rand.New(rand.NewPCG(seed, 0x636861736864696)) //nolint:gosec // deterministic test data
	var g *diffTree
	ref := createRefFunc(t, cm, func(root string) error {
		var err error
		g, err = generateDiffTree(r, root)
		return err
	})
	queries := g.queries(r)

	defer setChecksumConcurrency(checksumConcurrency)

	setChecksumConcurrency(1)
	want := make([]diffResult, len(queries))
	for i, q := range queries {
		cc := emptyCacheContext(ref)
		m := &mount{mountable: ref}
		cc.mu.Lock()
		require.NoError(t, cc.scanPath(t.Context(), m, "", false))
		cc.mu.Unlock()
		require.NoError(t, m.clean())
		want[i] = q.run(t, cc, ref)
	}
	var nerr int
	for _, w := range want {
		if w.err != nil {
			nerr++
		}
	}
	t.Logf("%d paths, %d queries, %d errors", len(g.paths), len(queries), nerr)

	check := func(mode string, i int, got diffResult) {
		t.Helper()
		w := want[i]
		if w.err != nil || got.err != nil {
			require.Equalf(t, w.err != nil, got.err != nil, "%s: %s: want err %v, got err %v", mode, queries[i], w.err, got.err)
			return
		}
		require.Equalf(t, w.dgst, got.dgst, "%s: %s", mode, queries[i])
	}

	for _, conc := range []int{1, 2, 8} {
		setChecksumConcurrency(conc)

		// A new context for every query.
		for i, q := range queries {
			check(fmt.Sprintf("fresh conc=%d", conc), i, q.run(t, emptyCacheContext(ref), ref))
		}

		// One context shared across all queries, in several orders, then
		// persisted and loaded again.
		for round := range 3 {
			order := r.Perm(len(queries))
			if round == 0 {
				for i := range order {
					order[i] = i
				}
			}
			cc := emptyCacheContext(ref)
			for _, i := range order {
				check(fmt.Sprintf("shared conc=%d round=%d", conc, round), i, queries[i].run(t, cc, ref))
			}
			require.NoError(t, cc.save())
			cc2, err := newCacheContext(ref)
			require.NoError(t, err)
			for _, i := range r.Perm(len(queries)) {
				check(fmt.Sprintf("loaded conc=%d round=%d", conc, round), i, queries[i].run(t, cc2, ref))
			}
		}
	}

	// All queries at once on one context.
	setChecksumConcurrency(4)
	cc := emptyCacheContext(ref)
	results := make([]diffResult, len(queries))
	var wg sync.WaitGroup
	for i, q := range queries {
		wg.Go(func() {
			results[i] = q.run(t, cc, ref)
		})
	}
	wg.Wait()
	for i, res := range results {
		check("concurrent", i, res)
	}
}

func setChecksumConcurrency(n int) {
	checksumConcurrency = n
}

func emptyCacheContext(ref cache.ImmutableRef) *cacheContext {
	return &cacheContext{
		md:       cacheMetadata{ref},
		tree:     iradix.New[*CacheRecord](),
		dirtyMap: map[string]struct{}{},
		linkMap:  map[string][][]byte{},
	}
}

type diffQuery struct {
	path string
	opts ChecksumOpts
}

func (q diffQuery) String() string {
	return fmt.Sprintf("%q follow=%v wildcard=%v include=%q exclude=%q required=%q",
		q.path, q.opts.FollowLinks, q.opts.Wildcard, q.opts.IncludePatterns, q.opts.ExcludePatterns, q.opts.RequiredPaths)
}

type diffResult struct {
	dgst digest.Digest
	err  error
}

func (q diffQuery) run(t *testing.T, cc *cacheContext, ref cache.ImmutableRef) diffResult {
	dgst, err := cc.Checksum(t.Context(), ref, q.path, q.opts, nil)
	return diffResult{dgst: dgst, err: err}
}

// diffNames are the names used in generated trees. They are few, so that
// wildcards and patterns match several entries, and include characters that
// are special in patterns.
var diffNames = []string{"a", "b", "ab", "a.go", "b.go", "x.txt", "lib", "node_modules", "[x]", "sp ace", "d.d", "e"}

type diffTree struct {
	r     *rand.Rand
	root  string
	paths []string // every created path
	files []string // regular files, as hardlink sources
	links []string // symlinks
	dirs  []string
}

func generateDiffTree(r *rand.Rand, root string) (*diffTree, error) {
	g := &diffTree{r: r, root: root}
	if err := g.fillDir("/", 0); err != nil {
		return nil, err
	}
	// Some symlinks are created last, so they can point at anything.
	for range 4 + r.IntN(4) {
		dir := "/"
		if len(g.dirs) > 0 && r.IntN(3) > 0 {
			dir = g.dirs[r.IntN(len(g.dirs))]
		}
		p := path.Join(dir, "ln"+fmt.Sprint(len(g.links)))
		if err := g.symlink(p); err != nil {
			return nil, err
		}
	}
	return g, nil
}

func (g *diffTree) fillDir(dir string, depth int) error {
	n := g.r.IntN(7)
	if depth == 0 {
		n = 6 + g.r.IntN(6)
	}
	names := append([]string(nil), diffNames...)
	g.r.Shuffle(len(names), func(i, j int) { names[i], names[j] = names[j], names[i] })
	for _, name := range names[:n] {
		p := path.Join(dir, name)
		fp := filepath.Join(g.root, filepath.FromSlash(p))
		switch roll := g.r.IntN(100); {
		case roll < 35 && depth < 4:
			if err := os.Mkdir(fp, 0755); err != nil {
				return err
			}
			g.paths = append(g.paths, p)
			g.dirs = append(g.dirs, p)
			if err := g.fillDir(p, depth+1); err != nil {
				return err
			}
			if g.r.IntN(5) == 0 {
				if err := os.Chmod(fp, 0700); err != nil {
					return err
				}
			}
		case roll < 80 || len(g.files) == 0:
			if err := os.WriteFile(fp, g.content(), []os.FileMode{0644, 0755, 0600, 0444}[g.r.IntN(4)]); err != nil {
				return err
			}
			g.paths = append(g.paths, p)
			g.files = append(g.files, p)
		case roll < 92:
			if err := g.symlink(p); err != nil {
				return err
			}
		default:
			src := g.files[g.r.IntN(len(g.files))]
			if err := os.Link(filepath.Join(g.root, filepath.FromSlash(src)), fp); err != nil {
				return err
			}
			g.paths = append(g.paths, p)
		}
	}
	return nil
}

func (g *diffTree) content() []byte {
	var n int
	switch g.r.IntN(4) {
	case 0:
	case 1:
		n = 1 + g.r.IntN(100)
	case 2:
		n = 1000 + g.r.IntN(8000)
	case 3:
		n = 33000 + g.r.IntN(40000) // larger than the copy buffer
	}
	dt := make([]byte, n)
	for i := range dt {
		dt[i] = byte(g.r.IntN(4)) + 'a'
	}
	return dt
}

func (g *diffTree) randomPath() string {
	if len(g.paths) > 0 && g.r.IntN(4) > 0 {
		return g.paths[g.r.IntN(len(g.paths))]
	}
	p := "/"
	for range 1 + g.r.IntN(3) {
		p = path.Join(p, diffNames[g.r.IntN(len(diffNames))])
	}
	return p
}

func (g *diffTree) symlink(p string) error {
	var target string
	switch g.r.IntN(9) {
	case 0:
		target = "/"
	case 1:
		target = ".."
	case 2:
		target = "../../../.."
	case 3:
		target = "."
	case 4:
		target = "missing"
	case 5:
		target = path.Base(p) // loop
	case 6:
		rel, err := filepath.Rel(path.Dir(p), g.randomPath())
		if err != nil {
			return err
		}
		target = rel
	default:
		target = g.randomPath()
	}
	if err := os.Symlink(target, filepath.Join(g.root, filepath.FromSlash(p))); err != nil {
		return err
	}
	g.paths = append(g.paths, p)
	g.links = append(g.links, p)
	return nil
}

var diffPatterns = [][]string{
	{"*.go"},
	{"**/*.txt"},
	{"a"},
	{"lib/**"},
	{"node_modules"},
	{"**/b"},
	{"a*", "!ab"},
	{"*/a.go"},
}

func (g *diffTree) queries(r *rand.Rand) []diffQuery {
	paths := []string{"/", ""}
	paths = append(paths, g.paths...)
	for _, l := range g.links {
		paths = append(paths, l+"/a", l+"/lib/b.go")
	}
	for range 10 {
		paths = append(paths, g.randomPath()+"/"+diffNames[r.IntN(len(diffNames))])
	}
	for _, d := range g.dirs {
		paths = append(paths, d+"/")
	}

	var qs []diffQuery
	for _, p := range paths {
		qs = append(qs, diffQuery{path: p, opts: ChecksumOpts{FollowLinks: r.IntN(2) == 0}})
	}

	// Wildcards built from existing paths.
	for range 25 {
		p := g.randomPath()
		dir, base := path.Split(p)
		var w string
		switch r.IntN(5) {
		case 0:
			w = dir + "*"
		case 1:
			w = dir + base[:1] + "*"
		case 2:
			w = path.Join(path.Dir(path.Clean(dir)), "*", base)
		case 3:
			w = dir + "[ab]*"
		case 4:
			w = "/*/" + base
		}
		qs = append(qs, diffQuery{path: w, opts: ChecksumOpts{Wildcard: true, FollowLinks: r.IntN(2) == 0}})
	}

	// Include and exclude patterns, with and without wildcards.
	for range 25 {
		p := g.randomPath()
		if r.IntN(4) == 0 {
			p = "/"
		}
		opts := ChecksumOpts{FollowLinks: r.IntN(2) == 0}
		switch r.IntN(3) {
		case 0:
			opts.IncludePatterns = diffPatterns[r.IntN(len(diffPatterns))]
		case 1:
			opts.ExcludePatterns = diffPatterns[r.IntN(len(diffPatterns))]
		case 2:
			opts.IncludePatterns = diffPatterns[r.IntN(len(diffPatterns))]
			opts.ExcludePatterns = diffPatterns[r.IntN(len(diffPatterns))]
		}
		if r.IntN(3) == 0 {
			opts.Wildcard = true
			p = path.Dir(p) + "/*"
		}
		if r.IntN(5) == 0 {
			opts.RequiredPaths = []string{strings.TrimPrefix(g.randomPath(), "/")}
		}
		qs = append(qs, diffQuery{path: p, opts: opts})
	}
	return qs
}
