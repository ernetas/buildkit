package resolver

import (
	"bytes"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/moby/buildkit/session"
	digest "github.com/opencontainers/go-digest"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func TestPoolFetchConfig(t *testing.T) {
	blob := make([]byte, 1<<20)
	_, err := rand.Read(blob)
	require.NoError(t, err)
	dgst := digest.FromBytes(blob)
	desc := ocispecs.Descriptor{
		MediaType: ocispecs.MediaTypeImageLayerGzip,
		Digest:    dgst,
		Size:      int64(len(blob)),
	}

	var mu sync.Mutex
	var ranges []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v2/test/blobs/"+dgst.String() {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		ranges = append(ranges, r.Header.Get("Range"))
		mu.Unlock()
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(blob))
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	ref := u.Host + "/test:latest"

	hosts := func(string) ([]docker.RegistryHost, error) {
		return []docker.RegistryHost{{
			Client:       srv.Client(),
			Host:         u.Host,
			Scheme:       "http",
			Path:         "/v2",
			Capabilities: docker.HostCapabilityResolve | docker.HostCapabilityPull,
		}}, nil
	}

	fetch := func(t *testing.T, r *Resolver) []string {
		mu.Lock()
		ranges = nil
		mu.Unlock()
		f, err := r.Fetcher(t.Context(), ref)
		require.NoError(t, err)
		rc, err := f.Fetch(t.Context(), desc)
		require.NoError(t, err)
		dt, err := io.ReadAll(rc)
		require.NoError(t, err)
		require.NoError(t, rc.Close())
		require.Equal(t, dgst, digest.FromBytes(dt))
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), ranges...)
	}

	t.Run("default", func(t *testing.T) {
		p := NewPool()
		got := fetch(t, p.GetResolver(hosts, ref, ScopeType{}, nil, nil))
		require.Equal(t, []string{""}, got)
	})

	t.Run("parallel", func(t *testing.T) {
		p := NewPool()
		p.SetFetchConfig(FetchConfig{Parallelism: 4, ChunkSize: 256 << 10})
		r := p.GetResolver(hosts, ref, ScopeType{}, nil, nil)
		got := fetch(t, r)
		require.ElementsMatch(t, []string{"bytes=0-", "bytes=262144-", "bytes=524288-", "bytes=786432-"}, got)

		// a resolver rebound to another session keeps the fetch config
		got = fetch(t, r.WithSession(session.NewGroup("other")))
		require.Len(t, got, 4)
	})

	t.Run("parallelism one", func(t *testing.T) {
		p := NewPool()
		p.SetFetchConfig(FetchConfig{Parallelism: 1, ChunkSize: 256 << 10})
		got := fetch(t, p.GetResolver(hosts, ref, ScopeType{}, nil, nil))
		require.Equal(t, []string{""}, got)
	})

	t.Run("blob smaller than chunk", func(t *testing.T) {
		p := NewPool()
		p.SetFetchConfig(FetchConfig{Parallelism: 4})
		got := fetch(t, p.GetResolver(hosts, ref, ScopeType{}, nil, nil))
		require.Len(t, got, 1)
		require.True(t, got[0] == "" || strings.HasPrefix(got[0], "bytes=0-"), got[0])
	})
}
