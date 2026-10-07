package remotecache

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/containerd/containerd/v2/core/content"
	v1 "github.com/moby/buildkit/cache/remotecache/v1"
	cacheimporttypes "github.com/moby/buildkit/cache/remotecache/v1/types"
	"github.com/moby/buildkit/util/bklog"
	"github.com/moby/buildkit/util/progress"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

// MergeSource reads the cache that an export is about to replace.
type MergeSource interface {
	// Resolve returns the descriptor of the cache manifest currently at the
	// export target, and a provider for it and everything it references. A
	// zero descriptor means there is no cache there yet.
	Resolve(ctx context.Context) (ocispecs.Descriptor, content.Provider, error)
}

type mergeConfig struct {
	src MergeSource
	opt v1.MergeOpt
}

// mergePrevious merges the cache currently at the export target into config.
// Merging is best effort: on any error the export goes ahead with config as
// it is, as it would without merging.
func (m *mergeConfig) mergePrevious(ctx context.Context, config *cacheimporttypes.CacheConfig, descs v1.DescriptorProvider) (*cacheimporttypes.CacheConfig, v1.DescriptorProvider) {
	prev, prevDescs, err := m.loadPrevious(ctx)
	if err == nil && prev == nil {
		return config, descs
	}
	var merged *cacheimporttypes.CacheConfig
	var mergedDescs v1.DescriptorProvider
	var stats v1.MergeStats
	if err == nil {
		merged, mergedDescs, stats, err = v1.Merge(ctx, config, descs, prev, prevDescs, m.opt)
	}
	if err != nil {
		bklog.G(ctx).WithError(err).Warn("failed to merge previous cache, exporting without it")
		progress.OneOff(ctx, fmt.Sprintf("skipping merge of previous cache: %v", err))(nil)
		return config, descs
	}
	progress.OneOff(ctx, fmt.Sprintf("merged %d of %d previous cache records (config %d bytes)", stats.AddedRecords, stats.PrevRecords, stats.Size))(nil)
	return merged, mergedDescs
}

func (m *mergeConfig) loadPrevious(ctx context.Context) (*cacheimporttypes.CacheConfig, v1.DescriptorProvider, error) {
	desc, provider, err := m.src.Resolve(ctx)
	if err != nil {
		return nil, nil, err
	}
	if desc.Digest == "" {
		return nil, nil, nil
	}
	dt, err := readBlob(ctx, provider, desc)
	if err != nil {
		return nil, nil, err
	}
	_, configDesc, layers, err := parseCacheManifest(dt, provider)
	if err != nil {
		return nil, nil, err
	}
	if configDesc.Digest == "" {
		return nil, nil, errors.Errorf("%s is not a cache manifest", desc.Digest)
	}
	dt, err = readBlob(ctx, provider, configDesc)
	if err != nil {
		return nil, nil, err
	}
	var cfg cacheimporttypes.CacheConfig
	if err := json.Unmarshal(dt, &cfg); err != nil {
		return nil, nil, errors.WithStack(err)
	}
	return &cfg, layers, nil
}
