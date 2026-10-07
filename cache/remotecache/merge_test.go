package remotecache

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	v1 "github.com/moby/buildkit/cache/remotecache/v1"
	cacheimporttypes "github.com/moby/buildkit/cache/remotecache/v1/types"
	"github.com/moby/buildkit/solver"
	"github.com/moby/buildkit/util/compression"
	"github.com/moby/buildkit/util/contentutil"
	digest "github.com/opencontainers/go-digest"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

type testMergeSource struct {
	desc     ocispecs.Descriptor
	provider content.Provider
	err      error
}

func (s *testMergeSource) Resolve(context.Context) (ocispecs.Descriptor, content.Provider, error) {
	return s.desc, s.provider, s.err
}

func TestExportMerge(t *testing.T) {
	ctx := t.Context()
	store := contentutil.NewBuffer()
	now := time.Now()

	// export adds one record keyed by name, with a single-layer result, and
	// returns the manifest it wrote and the config it references.
	export := func(name string, opts ...ExporterOpt) (ocispecs.Descriptor, cacheimporttypes.CacheConfig) {
		blob := []byte("layer " + name)
		desc := ocispecs.Descriptor{Digest: digest.FromBytes(blob), Size: int64(len(blob)), MediaType: ocispecs.MediaTypeImageLayerGzip}
		require.NoError(t, content.WriteBlob(ctx, store, desc.Digest.String(), bytes.NewReader(blob), desc))

		e := NewExporter(store, "", true, true, compression.New(compression.Default), opts...)
		_, _, err := e.Add(digest.FromString(name), nil, []solver.CacheExportResult{{
			CreatedAt: now,
			Result:    &solver.Remote{Descriptors: []ocispecs.Descriptor{desc}, Provider: store},
		}})
		require.NoError(t, err)
		res, err := e.Finalize(ctx)
		require.NoError(t, err)

		var mfstDesc ocispecs.Descriptor
		require.NoError(t, json.Unmarshal([]byte(res[ExporterResponseManifestDesc]), &mfstDesc))
		dt, err := content.ReadBlob(ctx, store, mfstDesc)
		require.NoError(t, err)
		var mfst ocispecs.Manifest
		require.NoError(t, json.Unmarshal(dt, &mfst))
		dt, err = content.ReadBlob(ctx, store, mfst.Config)
		require.NoError(t, err)
		var cfg cacheimporttypes.CacheConfig
		require.NoError(t, json.Unmarshal(dt, &cfg))
		require.Len(t, mfst.Layers, len(cfg.Layers))
		return mfstDesc, cfg
	}
	keys := func(cfg cacheimporttypes.CacheConfig) (out []digest.Digest) {
		for _, r := range cfg.Records {
			out = append(out, r.Digest)
		}
		return out
	}

	prevDesc, _ := export("a")

	// Without a previous cache, or when it can't be read, the export only
	// has its own records.
	_, cfg := export("b", WithMerge(&testMergeSource{}, v1.MergeOpt{}))
	require.ElementsMatch(t, []digest.Digest{digest.FromString("b")}, keys(cfg))
	_, cfg = export("b", WithMerge(&testMergeSource{err: errors.New("unreachable")}, v1.MergeOpt{}))
	require.ElementsMatch(t, []digest.Digest{digest.FromString("b")}, keys(cfg))

	// With merge, the records of the previous cache are carried over and its
	// layers are listed in the new manifest.
	_, cfg = export("b", WithMerge(&testMergeSource{desc: prevDesc, provider: store}, v1.MergeOpt{}))
	require.ElementsMatch(t, []digest.Digest{digest.FromString("a"), digest.FromString("b")}, keys(cfg))
	require.Len(t, cfg.Layers, 2)
}
