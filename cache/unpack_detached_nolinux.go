//go:build !linux

package cache

import (
	"context"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/mount"
	digest "github.com/opencontainers/go-digest"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

type layerDirs struct {
	implicit []string
	unsafe   bool
}

func detachedApplySupported(string) bool {
	return false
}

func applyToUpper(context.Context, content.Provider, ocispecs.Descriptor, []mount.Mount) (digest.Digest, *layerDirs, error) {
	return "", nil, errors.New("detached apply is not supported on this platform")
}

func fixupImplicitDirs(string, []string, *layerDirs) error {
	return errors.New("detached apply is not supported on this platform")
}

func lowerDirs([]mount.Mount) ([]string, error) {
	return nil, errors.New("detached apply is not supported on this platform")
}
