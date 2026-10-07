package contenthash

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync/atomic"

	iradix "github.com/hashicorp/go-immutable-radix/v2"
	digest "github.com/opencontainers/go-digest"
	"golang.org/x/sync/errgroup"
)

// checksumConcurrency bounds how many files a single checksum request hashes
// at the same time. It is larger than GOMAXPROCS because hashing a small file
// mostly waits in lstat, open, llistxattr and read, which do not hold a P.
var checksumConcurrency = min(2*runtime.GOMAXPROCS(0), 32)

type hashTarget struct {
	k    []byte
	cr   *CacheRecord
	dgst digest.Digest
}

// prehash computes, in parallel, the digests of the records that checksum()
// would otherwise hash one by one for the given keys, and returns tree with
// those digests filled in. The serial fold in checksum() then only has to
// combine digests that are already in the tree, so the resulting digests are
// identical to a serial run.
//
// Hashing errors are not returned: the digests computed so far are dropped
// and the serial fold hits, and reports, the same error at the same point it
// always did. Only a cancelled context is returned as an error.
func (cc *cacheContext) prehash(ctx context.Context, tree *iradix.Tree[*CacheRecord], m *mount, keys [][]byte, followTrailing bool) (*iradix.Tree[*CacheRecord], bool, error) {
	if checksumConcurrency < 2 {
		return tree, false, nil
	}
	root := tree.Root()
	var targets []hashTarget
	seen := map[string]struct{}{}
	add := func(k []byte, cr *CacheRecord) {
		if _, ok := seen[string(k)]; ok {
			return
		}
		seen[string(k)] = struct{}{}
		targets = append(targets, hashTarget{k: k, cr: cr})
	}
	for _, k := range keys {
		collectHashTargets(root, k, followTrailing, add)
	}
	if len(targets) < 2 {
		return tree, false, nil
	}

	mp, err := m.mount(ctx)
	if err != nil {
		return tree, false, nil
	}

	var next atomic.Int64
	eg, egCtx := errgroup.WithContext(ctx)
	for range min(checksumConcurrency, len(targets)) {
		eg.Go(func() error {
			for {
				i := int(next.Add(1) - 1)
				if i >= len(targets) {
					return nil
				}
				if err := context.Cause(egCtx); err != nil {
					return err
				}
				t := &targets[i]
				// Same as the default case in checksum().
				p := convertKeyToPath(bytes.TrimSuffix(t.k, []byte{0}))
				fp := filepath.Join(mp, filepath.FromSlash(p))
				fi, err := os.Lstat(fp)
				if err != nil {
					return err
				}
				t.dgst, err = prepareDigest(fp, p, fi)
				if err != nil {
					return err
				}
			}
		})
	}
	if err := eg.Wait(); err != nil {
		if err := context.Cause(ctx); err != nil {
			return nil, false, err
		}
		return tree, false, nil
	}

	txn := tree.Txn()
	for _, t := range targets {
		txn.Insert(t.k, &CacheRecord{
			Digest:   string(t.dgst),
			Type:     t.cr.Type,
			Linkname: t.cr.Linkname,
		})
	}
	return txn.Commit(), true, nil
}

// collectHashTargets mirrors the traversal of checksum(): it resolves k the
// same way and calls add for every record checksum() would hash (any
// non-directory record without a digest), skipping the subtrees of
// directories that already have one. It returns the resolved record, or nil
// if k does not resolve, in which case checksum() would fail.
func collectHashTargets(root *iradix.Node[*CacheRecord], k []byte, followTrailing bool, add func([]byte, *CacheRecord)) *CacheRecord {
	k, cr, err := getFollowLinks(root, k, followTrailing)
	if err != nil || cr == nil {
		return nil
	}
	if cr.Digest != "" {
		return cr
	}
	if cr.Type != CacheRecordTypeDir {
		add(k, cr)
		return cr
	}
	next := append(slices.Clone(k), 0)
	iter := root.Iterator()
	iter.SeekLowerBound(append(slices.Clone(next), 0))
	subk := next
	ok := true
	for ok && bytes.HasPrefix(subk, next) {
		subcr := collectHashTargets(root, subk, false, add)
		if subcr == nil {
			// checksum() fails here, nothing after this point is hashed.
			return cr
		}
		if subcr.Type == CacheRecordTypeDir {
			iter = root.Iterator()
			iter.SeekLowerBound(append(slices.Clone(subk), 0, 0xff))
		}
		subk, _, ok = iter.Next()
	}
	return cr
}
