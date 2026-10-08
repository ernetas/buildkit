package resolver

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/containerd/v2/core/transfer"
	cerrdefs "github.com/containerd/errdefs"
	distreference "github.com/distribution/reference"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/solver/pb"
	log "github.com/moby/buildkit/util/bklog"
	"github.com/moby/buildkit/version"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// DefaultPool is the default shared resolver pool instance
var DefaultPool = NewPool()

// Pool is a cache of recently used resolvers
type Pool struct {
	mu    sync.Mutex
	m     map[string]*authHandlerNS
	fetch FetchConfig
}

// FetchConfig controls how resolvers created by a Pool download blobs. The
// zero value downloads every blob with a single request.
//
// With Parallelism > 1 the containerd fetcher splits a blob into ChunkSize
// range requests and runs up to Parallelism of them at once. That helps when
// a single connection is slower than the link, for example behind a CDN that
// limits every stream, but it costs memory and connections: the requests for
// one blob share the blob's slot in the limited package, every chunk that is
// downloaded ahead of the reader is buffered in memory, and every chunk uses
// a new connection because the fetcher asks for an open-ended range and
// closes the response after ChunkSize bytes.
type FetchConfig struct {
	// Parallelism is the maximum number of concurrent range requests used to
	// download a single blob. Values below 2 disable range requests.
	Parallelism int
	// ChunkSize is the size in bytes of each range request. Blobs no larger
	// than one chunk use a single request. Zero means DefaultFetchChunkSize.
	ChunkSize int
}

// DefaultFetchChunkSize is the range request size used when
// FetchConfig.ChunkSize is not set.
const DefaultFetchChunkSize = 8 << 20

func (c FetchConfig) resolverOptions() []transfer.ImageResolverOption {
	if c.Parallelism < 2 {
		return nil
	}
	chunkSize := c.ChunkSize
	if chunkSize <= 0 {
		chunkSize = DefaultFetchChunkSize
	}
	return []transfer.ImageResolverOption{
		transfer.WithMaxConcurrentDownloads(c.Parallelism),
		transfer.WithConcurrentLayerFetchBuffer(chunkSize),
	}
}

// SetFetchConfig sets the blob download settings for resolvers created
// by the pool from now on.
func (p *Pool) SetFetchConfig(c FetchConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fetch = c
}

// NewPool creates a new pool for caching resolvers
func NewPool() *Pool {
	p := &Pool{
		m: map[string]*authHandlerNS{},
	}
	time.AfterFunc(5*time.Minute, p.gc)
	return p
}

func (p *Pool) gc() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for k, ns := range p.m {
		ns.muHandlers.Lock()
		for key, h := range ns.fetchers {
			if time.Since(h.lastUsed) < 10*time.Minute {
				continue
			}
			parts := strings.SplitN(key, "/", 2)
			if len(parts) != 2 {
				delete(ns.fetchers, key)
				continue
			}
			c, err := ns.sm.Get(context.TODO(), parts[1], true)
			if c == nil || err != nil {
				delete(ns.fetchers, key)
			}
		}
		if len(ns.fetchers) == 0 {
			delete(p.m, k)
		}
		ns.muHandlers.Unlock()
	}

	time.AfterFunc(5*time.Minute, p.gc)
}

// Clear deletes currently cached items. This may be called on config changes for example.
func (p *Pool) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.m = map[string]*authHandlerNS{}
}

// GetResolver gets a resolver for a specified scope from the pool
func (p *Pool) GetResolver(hosts docker.RegistryHosts, ref string, scope ScopeType, sm *session.Manager, g session.Group) *Resolver {
	name := ref
	named, err := distreference.ParseNormalizedNamed(ref)
	if err == nil {
		name = named.Name()
	}

	var key string
	if scope.Push {
		// When scope includes "push", index the authHandlerNS cache by session
		// id(s) as well to prevent tokens with potential write access to third
		// party registries from leaking between client sessions. The key will end
		// up looking something like:
		// 'wujskoey891qc5cv1edd3yj3p::repository:foo/bar::pull,push'
		key = fmt.Sprintf("%s::%s::%s", strings.Join(session.AllSessionIDs(g), ":"), name, scope.String())
	} else {
		// The authHandlerNS is not isolated for pull-only scopes since LLB
		// verticies from pulls all end up in the cache anyway and all
		// requests/clients have access to the same cache
		key = fmt.Sprintf("%s::%s", name, scope.String())
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	h, ok := p.m[key]

	if !ok {
		h = newAuthHandlerNS(sm)
		p.m[key] = h
	}

	log.G(context.TODO()).WithFields(logrus.Fields{
		"name":   name,
		"scope":  scope,
		"key":    key,
		"cached": ok,
	}).Debugf("checked for cached auth handler namespace")

	return newResolver(hosts, h, sm, g, p.fetch)
}

func newResolver(hosts docker.RegistryHosts, handler *authHandlerNS, sm *session.Manager, g session.Group, fetch FetchConfig) *Resolver {
	if hosts == nil {
		hosts = docker.ConfigureDefaultRegistries(
			docker.WithClient(newDefaultClient()),
			docker.WithPlainHTTP(docker.MatchLocalhost),
		)
	}
	headers := http.Header{}
	headers.Set("User-Agent", version.UserAgent())
	r := &Resolver{
		hosts:   hosts,
		sm:      sm,
		g:       g,
		handler: handler,
		headers: headers,
		fetch:   fetch,
	}
	r.Resolver = r.newDockerResolver()
	return r
}

// newDockerResolver creates the containerd resolver that r wraps. It must be
// called again whenever HostsFunc or the headers need to be rebound.
func (r *Resolver) newDockerResolver() remotes.Resolver {
	dr := docker.NewResolver(docker.ResolverOptions{
		Hosts:   r.HostsFunc,
		Headers: r.headers,
	})
	if opts := r.fetch.resolverOptions(); len(opts) > 0 {
		if dro, ok := dr.(remotes.ResolverWithOptions); ok {
			dro.SetOptions(opts...)
		}
	}
	return dr
}

type ScopeType struct {
	Push     bool
	Insecure bool
}

func (s ScopeType) String() string {
	out := "pull"
	if s.Push {
		out = "push"
	}
	if s.Insecure {
		out += ":insecure"
	}
	return out
}

// Resolver is a wrapper around remotes.Resolver
type Resolver struct {
	remotes.Resolver
	hosts   docker.RegistryHosts
	headers http.Header
	sm      *session.Manager
	g       session.Group
	handler *authHandlerNS
	auth    *dockerAuthorizer
	fetch   FetchConfig

	is   images.Store
	mode ResolveMode
}

// HostsFunc implements registry configuration of this Resolver
func (r *Resolver) HostsFunc(host string) ([]docker.RegistryHost, error) {
	return func(domain string) ([]docker.RegistryHost, error) {
		v, err := r.handler.g.Do(context.TODO(), domain, func(ctx context.Context) ([]docker.RegistryHost, error) {
			// long lock not needed because flightcontrol.Do
			r.handler.muHosts.Lock()
			v, ok := r.handler.hosts[domain]
			r.handler.muHosts.Unlock()
			if ok {
				return v, nil
			}
			res, err := r.hosts(domain)
			if err != nil {
				return nil, err
			}
			r.handler.muHosts.Lock()
			r.handler.hosts[domain] = res
			r.handler.muHosts.Unlock()
			return res, nil
		})
		if err != nil || v == nil {
			return nil, err
		}
		if len(v) == 0 {
			return nil, nil
		}
		// make a copy so authorizer is set on unique instance
		res := make([]docker.RegistryHost, len(v))
		copy(res, v)
		auth := newDockerAuthorizer(res[0].Client, r.handler, r.sm, r.g)
		for i := range res {
			res[i].Authorizer = auth
		}
		return res, nil
	}(host)
}

// WithSession returns a new resolver that works with new session group
func (r *Resolver) WithSession(s session.Group) *Resolver {
	r2 := *r
	r2.auth = nil
	r2.g = s
	r2.headers = r.headers.Clone()
	// HostsFunc refers to the newly-configured session so we need to recreate the resolver.
	r2.Resolver = r2.newDockerResolver()
	return &r2
}

// WithImageStore returns new resolver that can also resolve from local images store
func (r *Resolver) WithImageStore(is images.Store, mode ResolveMode) *Resolver {
	r2 := *r
	r2.Resolver = r.Resolver
	r2.is = is
	r2.mode = mode
	return &r2
}

// ResolveLocal attempts to resolve the reference from the local image store.
func (r *Resolver) ResolveLocal(ctx context.Context, ref string) (string, ocispecs.Descriptor, error) {
	if r.is == nil {
		return "", ocispecs.Descriptor{}, errors.WithStack(cerrdefs.ErrNotFound)
	}
	img, err := getImageByRef(ctx, r.is, ref)
	if err != nil {
		return "", ocispecs.Descriptor{}, err
	}
	return ref, img.Target, nil
}

// Fetcher returns a new fetcher for the provided reference.
func (r *Resolver) Fetcher(ctx context.Context, ref string) (remotes.Fetcher, error) {
	if r.handler.counter.Load() == 0 {
		r.Resolve(ctx, ref)
	}
	return r.Resolver.Fetcher(ctx, ref)
}

// Resolve attempts to resolve the reference into a name and descriptor.
func (r *Resolver) Resolve(ctx context.Context, ref string) (string, ocispecs.Descriptor, error) {
	if r.mode == ResolveModePreferLocal && r.is != nil {
		if ref, desc, err := r.ResolveLocal(ctx, ref); err == nil {
			return ref, desc, nil
		}
	}

	n, desc, err := r.Resolver.Resolve(ctx, ref)
	if err == nil {
		r.handler.counter.Add(1)
		return n, desc, nil
	}

	if r.mode == ResolveModeDefault && r.is != nil {
		if ref, desc, err := r.ResolveLocal(ctx, ref); err == nil {
			return ref, desc, nil
		}
	}

	return "", ocispecs.Descriptor{}, err
}

func getImageByRef(ctx context.Context, is images.Store, ref string) (images.Image, error) {
	named, err := distreference.ParseNormalizedNamed(ref)
	if err != nil {
		return images.Image{}, err
	}

	name := named.Name()
	tag := "latest"
	if t, ok := named.(distreference.Tagged); ok {
		tag = t.Tag()
	}
	name = name + ":" + tag
	img, err := is.Get(ctx, name)
	if err != nil {
		return images.Image{}, err
	}
	if c, ok := named.(distreference.Canonical); ok {
		if img.Target.Digest != c.Digest() {
			return images.Image{}, errors.WithStack(cerrdefs.ErrNotFound)
		}
	}
	return img, nil
}

type ResolveMode int

const (
	ResolveModeDefault ResolveMode = iota
	ResolveModeForcePull
	ResolveModePreferLocal
)

func (r ResolveMode) String() string {
	switch r {
	case ResolveModeDefault:
		return pb.AttrImageResolveModeDefault
	case ResolveModeForcePull:
		return pb.AttrImageResolveModeForcePull
	case ResolveModePreferLocal:
		return pb.AttrImageResolveModePreferLocal
	default:
		return ""
	}
}

func ParseImageResolveMode(v string) (ResolveMode, error) {
	switch v {
	case pb.AttrImageResolveModeDefault, "":
		return ResolveModeDefault, nil
	case pb.AttrImageResolveModeForcePull:
		return ResolveModeForcePull, nil
	case pb.AttrImageResolveModePreferLocal:
		return ResolveModePreferLocal, nil
	default:
		return 0, errors.Errorf("invalid resolvemode: %s", v)
	}
}
