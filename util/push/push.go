package push

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	cerrdefs "github.com/containerd/errdefs"
	"github.com/distribution/reference"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/util/bklog"
	"github.com/moby/buildkit/util/contentutil"
	"github.com/moby/buildkit/util/flightcontrol"
	"github.com/moby/buildkit/util/imageutil"
	"github.com/moby/buildkit/util/progress"
	"github.com/moby/buildkit/util/progress/logs"
	"github.com/moby/buildkit/util/resolver"
	resolverconfig "github.com/moby/buildkit/util/resolver/config"
	"github.com/moby/buildkit/util/resolver/limited"
	"github.com/moby/buildkit/util/resolver/retryhandler"
	digest "github.com/opencontainers/go-digest"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

type pusher struct {
	remotes.Pusher
}

// Pusher creates and new pusher instance for resolver
// containerd resolver.Pusher() method is broken and should not be called directly
// we need to wrap to mask interface detection
func Pusher(ctx context.Context, resolver remotes.Resolver, ref string) (remotes.Pusher, error) {
	p, err := resolver.Pusher(ctx, ref)
	if err != nil {
		return nil, err
	}
	return &pusher{Pusher: p}, nil
}

func newPusher(ctx context.Context, sm *session.Manager, sid string, parsed reference.Named, ref string, insecure bool, hosts docker.RegistryHosts) (remotes.Pusher, error) {
	scope := resolver.ScopeType{Push: true}
	if insecure {
		insecureTrue := true
		httpTrue := true
		hosts = resolver.NewRegistryConfig(map[string]resolverconfig.RegistryConfig{
			reference.Domain(parsed): {
				Insecure:  &insecureTrue,
				PlainHTTP: &httpTrue,
			},
		})
		scope.Insecure = true
	}

	resolver := resolver.DefaultPool.GetResolver(hosts, ref, scope, sm, session.NewGroup(sid))
	return Pusher(ctx, resolver, ref)
}

// Opt is an option for Push.
type Opt func(*pushOpts)

type pushOpts struct {
	uploader *BlobUploader
}

// WithBlobUploader makes Push wait for the blobs that uploader has been asked
// to upload, and skip the ones it uploaded successfully. uploader must upload
// to the repository that Push pushes to.
func WithBlobUploader(uploader *BlobUploader) Opt {
	return func(o *pushOpts) {
		o.uploader = uploader
	}
}

func Push(ctx context.Context, sm *session.Manager, sid string, provider content.Provider, manager content.Manager, dgst digest.Digest, ref string, insecure bool, hosts docker.RegistryHosts, byDigest bool, annotations map[digest.Digest]map[string]string, opts ...Opt) error {
	var o pushOpts
	for _, opt := range opts {
		opt(&o)
	}
	ctx = contentutil.RegisterContentPayloadTypes(ctx)
	desc := ocispecs.Descriptor{
		Digest: dgst,
	}
	parsed, err := reference.ParseNormalizedNamed(ref)
	if err != nil {
		return err
	}
	if byDigest && !reference.IsNameOnly(parsed) {
		return errors.Errorf("can't push tagged ref %s by digest", parsed.String())
	}

	if byDigest {
		ref = parsed.Name()
	} else {
		// add digest to ref, this is what containderd uses to choose root manifest from all manifests
		r, err := reference.WithDigest(reference.TagNameOnly(parsed), dgst)
		if err != nil {
			return errors.Wrapf(err, "failed to combine ref %s with digest %s", ref, dgst)
		}
		ref = r.String()
	}

	pusher, err := newPusher(ctx, sm, sid, parsed, ref, insecure, hosts)
	if err != nil {
		return err
	}

	dedupe := newDedupe()
	if o.uploader != nil {
		if o.uploader.repo != parsed.Name() {
			return errors.Errorf("blob uploader for %s can't be used to push %s", o.uploader.repo, parsed.Name())
		}
		dedupe = o.uploader.dedupe
	}

	var m sync.Mutex
	manifestStack := []ocispecs.Descriptor{}

	filterHandler := images.HandlerFunc(func(ctx context.Context, desc ocispecs.Descriptor) ([]ocispecs.Descriptor, error) {
		switch desc.MediaType {
		case images.MediaTypeDockerSchema2Manifest, ocispecs.MediaTypeImageManifest,
			images.MediaTypeDockerSchema2ManifestList, ocispecs.MediaTypeImageIndex:
			m.Lock()
			manifestStack = append(manifestStack, desc)
			m.Unlock()
			return nil, images.ErrStopHandler
		default:
			return nil, nil
		}
	})

	pushHandler := retryhandler.New(limited.PushHandler(pusher, provider, ref), logs.LoggerFromContext(ctx))
	pushUpdateSourceHandler, err := updateDistributionSourceHandler(manager, pushHandler, ref)
	if err != nil {
		return err
	}

	handlers := append([]images.Handler{},
		images.HandlerFunc(annotateDistributionSourceHandler(manager, annotations, childrenHandler(provider))),
		filterHandler,
		dedupe.handler(pushUpdateSourceHandler),
	)

	ra, err := provider.ReaderAt(ctx, desc)
	if err != nil {
		return err
	}

	mtype, err := imageutil.DetectManifestMediaType(ra)
	if err != nil {
		return err
	}

	layersDone := progress.OneOff(ctx, "pushing layers")
	if o.uploader != nil {
		// Wait for the blobs that are being uploaded early. The ones that
		// failed are retried by the dispatch below.
		o.uploader.Wait()
	}
	err = images.Dispatch(ctx, skipNonDistributableBlobs(images.Handlers(handlers...)), nil, ocispecs.Descriptor{
		Digest:    dgst,
		Size:      ra.Size(),
		MediaType: mtype,
	})
	if err := layersDone(err); err != nil {
		return err
	}

	mfstDone := progress.OneOff(ctx, fmt.Sprintf("pushing manifest for %s", ref))
	for _, desc := range slices.Backward(manifestStack) {
		if _, err := pushHandler(ctx, desc); err != nil {
			return mfstDone(err)
		}
	}
	return mfstDone(nil)
}

// TODO: the containerd function for this is filtering too much, that needs to be fixed.
// For now we just carry this.
func skipNonDistributableBlobs(f images.HandlerFunc) images.HandlerFunc {
	return func(ctx context.Context, desc ocispecs.Descriptor) ([]ocispecs.Descriptor, error) {
		if images.IsNonDistributable(desc.MediaType) {
			bklog.G(ctx).WithField("digest", desc.Digest).WithField("mediatype", desc.MediaType).Debug("Skipping non-distributable blob")
			return nil, images.ErrSkipDesc
		}
		return f(ctx, desc)
	}
}

func annotateDistributionSourceHandler(manager content.Manager, annotations map[digest.Digest]map[string]string, f images.HandlerFunc) func(ctx context.Context, desc ocispecs.Descriptor) ([]ocispecs.Descriptor, error) {
	return func(ctx context.Context, desc ocispecs.Descriptor) ([]ocispecs.Descriptor, error) {
		children, err := f(ctx, desc)
		if err != nil {
			return nil, err
		}

		// only add distribution source for the config or blob data descriptor
		switch desc.MediaType {
		case images.MediaTypeDockerSchema2Manifest, ocispecs.MediaTypeImageManifest,
			images.MediaTypeDockerSchema2ManifestList, ocispecs.MediaTypeImageIndex:
		default:
			return children, nil
		}

		for i := range children {
			child := children[i]

			if m, ok := annotations[child.Digest]; ok {
				for k, v := range m {
					if !strings.HasPrefix(k, "containerd.io/distribution.source.") {
						continue
					}
					if child.Annotations == nil {
						child.Annotations = map[string]string{}
					}
					child.Annotations[k] = v
				}
			}
			child, err := addDistributionSourceLabels(ctx, manager, child)
			if err != nil {
				return nil, err
			}
			children[i] = child
		}
		return children, nil
	}
}

// addDistributionSourceLabels copies the distribution source labels of desc
// in the content store to its annotations, so that the pusher can mount it
// from another repository.
func addDistributionSourceLabels(ctx context.Context, manager content.Manager, desc ocispecs.Descriptor) (ocispecs.Descriptor, error) {
	info, err := manager.Info(ctx, desc.Digest)
	if errors.Is(err, cerrdefs.ErrNotFound) {
		return desc, nil
	} else if err != nil {
		return desc, err
	}

	for k, v := range info.Labels {
		if !strings.HasPrefix(k, "containerd.io/distribution.source.") {
			continue
		}

		if desc.Annotations == nil {
			desc.Annotations = map[string]string{}
		}
		desc.Annotations[k] = v
	}
	return desc, nil
}

func childrenHandler(provider content.Provider) images.HandlerFunc {
	return func(ctx context.Context, desc ocispecs.Descriptor) ([]ocispecs.Descriptor, error) {
		var descs []ocispecs.Descriptor
		switch desc.MediaType {
		case images.MediaTypeDockerSchema2Manifest, ocispecs.MediaTypeImageManifest:
			p, err := content.ReadBlob(ctx, provider, desc)
			if err != nil {
				return nil, err
			}

			// TODO(stevvooe): We just assume oci manifest, for now. There may be
			// subtle differences from the docker version.
			var manifest ocispecs.Manifest
			if err := json.Unmarshal(p, &manifest); err != nil {
				return nil, err
			}

			descs = append(descs, manifest.Config)
			descs = append(descs, manifest.Layers...)
		case images.MediaTypeDockerSchema2ManifestList, ocispecs.MediaTypeImageIndex:
			p, err := content.ReadBlob(ctx, provider, desc)
			if err != nil {
				return nil, err
			}

			var index ocispecs.Index
			if err := json.Unmarshal(p, &index); err != nil {
				return nil, err
			}

			for _, m := range index.Manifests {
				if m.Digest != "" {
					descs = append(descs, m)
				}
			}
		case images.MediaTypeDockerSchema2Layer, images.MediaTypeDockerSchema2LayerGzip,
			images.MediaTypeDockerSchema2Config, ocispecs.MediaTypeImageConfig,
			ocispecs.MediaTypeImageLayer, ocispecs.MediaTypeImageLayerGzip,
			intoto.PayloadType:
			// childless data types.
			return nil, nil
		default:
			bklog.G(ctx).Warnf("encountered unknown type %v; children may not be fetched", desc.MediaType)
		}

		return descs, nil
	}
}

// updateDistributionSourceHandler will update distribution source label after
// pushing layer successfully.
//
// FIXME(fuweid): There is race condition for current design of distribution
// source label if there are pull/push jobs consuming same layer.
func updateDistributionSourceHandler(manager content.Manager, pushF images.HandlerFunc, ref string) (images.HandlerFunc, error) {
	updateF, err := docker.AppendDistributionSourceLabel(manager, ref)
	if err != nil {
		return nil, err
	}

	return images.HandlerFunc(func(ctx context.Context, desc ocispecs.Descriptor) ([]ocispecs.Descriptor, error) {
		var islayer bool

		switch desc.MediaType {
		case images.MediaTypeDockerSchema2Layer, images.MediaTypeDockerSchema2LayerGzip,
			ocispecs.MediaTypeImageLayer, ocispecs.MediaTypeImageLayerGzip:
			islayer = true
		}

		children, err := pushF(ctx, desc)
		if err != nil {
			return nil, err
		}

		// update distribution source to layer
		if islayer {
			if _, err := updateF(ctx, desc); err != nil {
				bklog.G(ctx).Warnf("failed to update distribution source for layer %v: %v", desc.Digest, err)
			}
		}
		return children, nil
	}), nil
}

// dedupe runs a handler once per digest. Handlers built from the same dedupe
// share the set of digests that were handled successfully.
type dedupe struct {
	g   flightcontrol.Group[[]ocispecs.Descriptor]
	mu  sync.Mutex
	res map[digest.Digest][]ocispecs.Descriptor
}

func newDedupe() *dedupe {
	return &dedupe{res: map[digest.Digest][]ocispecs.Descriptor{}}
}

func (d *dedupe) handler(h images.HandlerFunc) images.HandlerFunc {
	return images.HandlerFunc(func(ctx context.Context, desc ocispecs.Descriptor) ([]ocispecs.Descriptor, error) {
		return d.g.Do(ctx, desc.Digest.String(), func(ctx context.Context) ([]ocispecs.Descriptor, error) {
			d.mu.Lock()
			if r, ok := d.res[desc.Digest]; ok {
				d.mu.Unlock()
				return r, nil
			}
			d.mu.Unlock()

			children, err := h(ctx, desc)
			if err != nil {
				return nil, err
			}

			d.mu.Lock()
			d.res[desc.Digest] = children
			d.mu.Unlock()
			return children, nil
		})
	})
}

// BlobUploader uploads blobs to a repository as soon as they are ready, ahead
// of the Push of the image that references them. Pass it to Push with
// WithBlobUploader so that Push skips the blobs it has already uploaded.
//
// Uploads are best effort: a failed upload is logged, and retried by Push.
type BlobUploader struct {
	ctx     context.Context
	cancel  context.CancelCauseFunc
	repo    string
	manager content.Manager
	handler images.HandlerFunc
	dedupe  *dedupe
	wg      sync.WaitGroup
}

// NewBlobUploader returns a BlobUploader for the repository of ref. Uploads
// read the blobs from provider and stop when ctx is canceled or Close is
// called.
func NewBlobUploader(ctx context.Context, sm *session.Manager, sid string, provider content.Provider, manager content.Manager, ref string, insecure bool, hosts docker.RegistryHosts) (*BlobUploader, error) {
	ctx = contentutil.RegisterContentPayloadTypes(ctx)
	parsed, err := reference.ParseNormalizedNamed(ref)
	if err != nil {
		return nil, err
	}
	ref = reference.TagNameOnly(parsed).String()
	pusher, err := newPusher(ctx, sm, sid, parsed, ref, insecure, hosts)
	if err != nil {
		return nil, err
	}
	pushHandler := retryhandler.New(limited.PushHandler(pusher, provider, ref), logs.LoggerFromContext(ctx))
	pushUpdateSourceHandler, err := updateDistributionSourceHandler(manager, pushHandler, ref)
	if err != nil {
		return nil, err
	}
	d := newDedupe()
	ctx, cancel := context.WithCancelCause(ctx)
	return &BlobUploader{
		ctx:     ctx,
		cancel:  cancel,
		repo:    parsed.Name(),
		manager: manager,
		handler: skipNonDistributableBlobs(d.handler(pushUpdateSourceHandler)),
		dedupe:  d,
	}, nil
}

// Upload starts uploading desc in the background. Upload does not block.
func (u *BlobUploader) Upload(desc ocispecs.Descriptor) {
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		desc, err := addDistributionSourceLabels(u.ctx, u.manager, desc)
		if err == nil {
			_, err = u.handler(u.ctx, desc)
		}
		if err != nil && u.ctx.Err() == nil {
			bklog.G(u.ctx).WithError(err).WithField("digest", desc.Digest).Warn("early blob upload failed, retrying in push")
		}
	}()
}

// Wait waits for every upload started so far.
func (u *BlobUploader) Wait() {
	u.wg.Wait()
}

// Close cancels the uploads in progress and waits for them to return.
func (u *BlobUploader) Close() {
	u.cancel(errors.WithStack(context.Canceled))
	u.wg.Wait()
}
