package push

import (
	"bytes"
	"context"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/moby/buildkit/util/contentutil"
	digest "github.com/opencontainers/go-digest"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func TestUpdateDistributionSourceHandlerLabelsAllLayers(t *testing.T) {
	ctx := t.Context()
	const label = "containerd.io/distribution.source.registry.example.com"

	for _, tc := range []struct {
		mediaType string
		isLayer   bool
	}{
		{images.MediaTypeDockerSchema2Layer, true},
		{images.MediaTypeDockerSchema2LayerGzip, true},
		{images.MediaTypeDockerSchema2LayerZstd, true},
		{ocispecs.MediaTypeImageLayer, true},
		{ocispecs.MediaTypeImageLayerGzip, true},
		{ocispecs.MediaTypeImageLayerZstd, true},
		{ocispecs.MediaTypeImageConfig, false},
		{ocispecs.MediaTypeImageManifest, false},
	} {
		t.Run(tc.mediaType, func(t *testing.T) {
			cs := contentutil.NewBuffer()
			data := []byte("blob of " + tc.mediaType)
			desc := ocispecs.Descriptor{
				MediaType: tc.mediaType,
				Digest:    digest.FromBytes(data),
				Size:      int64(len(data)),
			}
			require.NoError(t, content.WriteBlob(ctx, cs, "ref", bytes.NewReader(data), desc))

			var pushed bool
			pushF := images.HandlerFunc(func(context.Context, ocispecs.Descriptor) ([]ocispecs.Descriptor, error) {
				pushed = true
				return nil, nil
			})
			h, err := updateDistributionSourceHandler(cs, pushF, "registry.example.com/foo/bar:latest")
			require.NoError(t, err)
			_, err = h(ctx, desc)
			require.NoError(t, err)
			require.True(t, pushed)

			info, err := cs.Info(ctx, desc.Digest)
			require.NoError(t, err)
			if tc.isLayer {
				require.Equal(t, "foo/bar", info.Labels[label])
			} else {
				require.Empty(t, info.Labels[label])
			}
		})
	}
}

func TestChildrenHandlerLayersAreChildless(t *testing.T) {
	ctx := t.Context()
	// The provider is empty: a layer must not be read to find its children.
	h := childrenHandler(contentutil.NewBuffer())
	for _, mt := range []string{
		images.MediaTypeDockerSchema2LayerGzip,
		images.MediaTypeDockerSchema2LayerZstd,
		ocispecs.MediaTypeImageLayer,
		ocispecs.MediaTypeImageLayerGzip,
		ocispecs.MediaTypeImageLayerZstd,
	} {
		children, err := h(ctx, ocispecs.Descriptor{MediaType: mt, Digest: digest.FromString(mt)})
		require.NoError(t, err, mt)
		require.Empty(t, children, mt)
	}
}
