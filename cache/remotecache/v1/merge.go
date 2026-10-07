package cacheimport

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	cacheimporttypes "github.com/moby/buildkit/cache/remotecache/v1/types"
	"github.com/pkg/errors"
)

// MergeOpt bounds how much of a previous cache config Merge carries over.
type MergeOpt struct {
	// MaxConfigSize is the largest merged config, in bytes of JSON. Records of
	// the previous config are dropped, oldest first, until the merged config
	// fits. If the current config alone is larger, nothing is merged.
	MaxConfigSize int
	// MaxAge drops records of the previous config whose newest result was
	// created longer ago than this, unless a kept record depends on them.
	// Zero keeps records of any age.
	MaxAge time.Duration
	// Now is the time MaxAge is measured from. Zero means time.Now().
	Now time.Time
}

// MergeStats describes what Merge did.
type MergeStats struct {
	// PrevRecords is the number of records in the previous config.
	PrevRecords int
	// AddedRecords is the number of records the merged config has on top of
	// the current one.
	AddedRecords int
	// Size is the size of the merged config in bytes.
	Size int
}

// Merge returns the union of the current cache config and the records of a
// previous config of the same ref, for example the one this export is about
// to replace. Records are matched by cache key and inputs, so a record both
// configs have appears once and its newest result wins, with the current
// config's result winning a tie. Previous records are kept newest first,
// together with the records they depend on, within opt.
//
// The previous config's blobs are assumed to be readable from prevDescs,
// usually because they are already in the target repository.
func Merge(ctx context.Context, cfg *cacheimporttypes.CacheConfig, descs DescriptorProvider, prev *cacheimporttypes.CacheConfig, prevDescs DescriptorProvider, opt MergeOpt) (*cacheimporttypes.CacheConfig, DescriptorProvider, MergeStats, error) {
	stats := MergeStats{PrevRecords: len(prev.Records)}

	union := func(prev *cacheimporttypes.CacheConfig) (*cacheimporttypes.CacheConfig, DescriptorProvider, int, error) {
		cc := NewCacheChains()
		if err := ParseConfig(*cfg, descs, cc); err != nil {
			return nil, nil, 0, err
		}
		if err := ParseConfig(*prev, prevDescs, cc); err != nil {
			return nil, nil, 0, errors.Wrap(err, "failed to parse previous cache config")
		}
		merged, mergedDescs, err := cc.Marshal(ctx)
		if err != nil {
			return nil, nil, 0, err
		}
		dt, err := json.Marshal(merged)
		if err != nil {
			return nil, nil, 0, err
		}
		return merged, mergedDescs, len(dt), nil
	}

	// Newest result of each previous record. Records without results stay
	// only as dependencies of kept records.
	newest := make([]time.Time, len(prev.Records))
	for i, rec := range prev.Records {
		for _, r := range rec.Results {
			if r.CreatedAt.After(newest[i]) {
				newest[i] = r.CreatedAt
			}
		}
		for _, r := range rec.ChainedResults {
			if r.CreatedAt.After(newest[i]) {
				newest[i] = r.CreatedAt
			}
		}
	}
	var cutoff time.Time
	if opt.MaxAge > 0 {
		now := opt.Now
		if now.IsZero() {
			now = time.Now()
		}
		cutoff = now.Add(-opt.MaxAge)
	}
	var thresholds []time.Time
	for _, t := range newest {
		if !t.IsZero() && !t.Before(cutoff) {
			thresholds = append(thresholds, t)
		}
	}
	slices.SortFunc(thresholds, func(a, b time.Time) int { return b.Compare(a) })
	thresholds = slices.Compact(thresholds)

	// Find the oldest threshold whose merged config still fits. Keeping more
	// records only grows the config, so a binary search over the thresholds,
	// newest first, finds it.
	var (
		best      *cacheimporttypes.CacheConfig
		bestDescs DescriptorProvider
		bestSize  int
	)
	lo, hi := 0, len(thresholds)-1
	for lo <= hi {
		mid := (lo + hi) / 2
		filtered := filterRecords(prev, newest, thresholds[mid])
		merged, mergedDescs, size, err := union(filtered)
		if err != nil {
			return nil, nil, stats, err
		}
		if opt.MaxConfigSize > 0 && size > opt.MaxConfigSize {
			hi = mid - 1
			continue
		}
		best, bestDescs, bestSize = merged, mergedDescs, size
		lo = mid + 1
	}
	if best == nil {
		// Nothing from the previous config fits. Export the current config as
		// it is, without the round trip.
		dt, err := json.Marshal(cfg)
		if err != nil {
			return nil, nil, stats, err
		}
		stats.Size = len(dt)
		return cfg, descs, stats, nil
	}
	stats.AddedRecords = max(len(best.Records)-len(cfg.Records), 0)
	stats.Size = bestSize
	return best, bestDescs, stats, nil
}

// filterRecords returns the records of cfg whose newest result is not older
// than threshold, plus every record they depend on. Indexes are remapped;
// layers are left as they are, since only the ones results refer to are
// marshaled.
func filterRecords(cfg *cacheimporttypes.CacheConfig, newest []time.Time, threshold time.Time) *cacheimporttypes.CacheConfig {
	keep := make([]bool, len(cfg.Records))
	var mark func(int)
	mark = func(i int) {
		if i < 0 || i >= len(cfg.Records) || keep[i] {
			return
		}
		keep[i] = true
		for _, inputs := range cfg.Records[i].Inputs {
			for _, in := range inputs {
				mark(in.LinkIndex)
			}
		}
	}
	for i, t := range newest {
		if !t.IsZero() && !t.Before(threshold) {
			mark(i)
		}
	}

	newIndex := make([]int, len(cfg.Records))
	out := &cacheimporttypes.CacheConfig{Layers: cfg.Layers}
	for i, rec := range cfg.Records {
		if !keep[i] {
			newIndex[i] = -1
			continue
		}
		newIndex[i] = len(out.Records)
		out.Records = append(out.Records, rec)
	}
	for i := range out.Records {
		rec := &out.Records[i]
		inputs := make([][]cacheimporttypes.CacheInput, len(rec.Inputs))
		for j, ins := range rec.Inputs {
			inputs[j] = make([]cacheimporttypes.CacheInput, 0, len(ins))
			for _, in := range ins {
				if in.LinkIndex >= 0 && in.LinkIndex < len(newIndex) && newIndex[in.LinkIndex] >= 0 {
					inputs[j] = append(inputs[j], cacheimporttypes.CacheInput{Selector: in.Selector, LinkIndex: newIndex[in.LinkIndex]})
				}
			}
		}
		rec.Inputs = inputs
	}
	return out
}
