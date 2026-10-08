package push

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/moby/buildkit/identity"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

// testRegistry is a minimal in-memory registry that records the uploads it
// receives.
type testRegistry struct {
	mu        sync.Mutex
	blobs     map[digest.Digest][]byte
	manifests map[string][]byte
	events    []string
	// failBlob makes the first upload of this blob fail.
	failBlob digest.Digest
}

func newTestRegistry(t *testing.T) (*testRegistry, string) {
	r := &testRegistry{blobs: map[digest.Digest][]byte{}, manifests: map[string][]byte{}}
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return r, strings.TrimPrefix(srv.URL, "http://")
}

func (r *testRegistry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := req.URL.Path
	switch {
	case p == "/v2/" || p == "/v2":
		w.WriteHeader(http.StatusOK)
	case strings.Contains(p, "/blobs/uploads/") && req.Method == http.MethodPost:
		w.Header().Set("Location", p+identity.NewID())
		w.WriteHeader(http.StatusAccepted)
	case strings.Contains(p, "/blobs/uploads/") && req.Method == http.MethodPut:
		dgst := digest.Digest(req.URL.Query().Get("digest"))
		dt, err := io.ReadAll(req.Body)
		if err != nil || digest.FromBytes(dt) != dgst {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.events = append(r.events, "blob "+dgst.String())
		if dgst == r.failBlob {
			r.failBlob = ""
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.blobs[dgst] = dt
		w.Header().Set("Docker-Content-Digest", dgst.String())
		w.WriteHeader(http.StatusCreated)
	case strings.Contains(p, "/blobs/"):
		dgst := digest.Digest(p[strings.LastIndex(p, "/")+1:])
		r.events = append(r.events, "check "+dgst.String())
		dt, ok := r.blobs[dgst]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Docker-Content-Digest", dgst.String())
		w.Header().Set("Content-Length", strconv.Itoa(len(dt)))
		w.WriteHeader(http.StatusOK)
	case strings.Contains(p, "/manifests/"):
		ref := p[strings.LastIndex(p, "/")+1:]
		switch req.Method {
		case http.MethodPut:
			dt, err := io.ReadAll(req.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			r.events = append(r.events, "manifest "+ref)
			r.manifests[ref] = dt
			r.manifests[digest.FromBytes(dt).String()] = dt
			w.Header().Set("Docker-Content-Digest", digest.FromBytes(dt).String())
			w.WriteHeader(http.StatusCreated)
		default:
			dt, ok := r.manifests[ref]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Docker-Content-Digest", digest.FromBytes(dt).String())
			w.Header().Set("Content-Type", ocispecs.MediaTypeImageManifest)
			w.Header().Set("Content-Length", strconv.Itoa(len(dt)))
			w.WriteHeader(http.StatusOK)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (r *testRegistry) snapshot() ([]string, map[digest.Digest][]byte, map[string][]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	blobs := map[digest.Digest][]byte{}
	for k, v := range r.blobs {
		blobs[k] = v
	}
	manifests := map[string][]byte{}
	for k, v := range r.manifests {
		manifests[k] = v
	}
	return append([]string(nil), r.events...), blobs, manifests
}

type testImage struct {
	cs       content.Store
	layers   []ocispecs.Descriptor
	manifest ocispecs.Descriptor
}

func newTestImage(t *testing.T) testImage {
	ctx := t.Context()
	cs, err := local.NewStore(t.TempDir())
	require.NoError(t, err)
	write := func(mediaType string, dt []byte) ocispecs.Descriptor {
		desc := ocispecs.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(dt), Size: int64(len(dt))}
		require.NoError(t, content.WriteBlob(ctx, cs, desc.Digest.String(), bytes.NewReader(dt), desc))
		return desc
	}
	var img testImage
	img.cs = cs
	for _, s := range []string{"layer one", "layer two", "layer three"} {
		img.layers = append(img.layers, write(ocispecs.MediaTypeImageLayerGzip, []byte(s)))
	}
	config := write(ocispecs.MediaTypeImageConfig, []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers"}}`))
	dt, err := json.Marshal(ocispecs.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispecs.MediaTypeImageManifest,
		Config:    config,
		Layers:    img.layers,
	})
	require.NoError(t, err)
	img.manifest = write(ocispecs.MediaTypeImageManifest, dt)
	return img
}

func countEventsList(events []string, prefix string) []string {
	var out []string
	for _, e := range events {
		if strings.HasPrefix(e, prefix) {
			out = append(out, e)
		}
	}
	return out
}

func countEvents(events []string, prefix string) map[string]int {
	m := map[string]int{}
	for _, e := range events {
		if strings.HasPrefix(e, prefix) {
			m[strings.TrimPrefix(e, prefix)]++
		}
	}
	return m
}

// TestPushWithBlobUploader checks that Push skips the blobs that a
// BlobUploader already uploaded, pushes the manifest only after every blob,
// and that the registry ends up with the same content as with a plain Push.
func TestPushWithBlobUploader(t *testing.T) {
	ctx := t.Context()
	img := newTestImage(t)

	plainReg, plainHost := newTestRegistry(t)
	require.NoError(t, Push(ctx, nil, "", img.cs, img.cs, img.manifest.Digest, plainHost+"/test/img:latest", true, nil, false, nil))

	reg, host := newTestRegistry(t)
	ref := host + "/test/img:latest"
	u, err := NewBlobUploader(ctx, nil, "", img.cs, img.cs, ref, true, nil)
	require.NoError(t, err)
	defer u.Close()
	u.Upload(img.layers[0])
	u.Upload(img.layers[2])
	u.Wait()

	events, _, _ := reg.snapshot()
	require.ElementsMatch(t, []string{"blob " + img.layers[0].Digest.String(), "blob " + img.layers[2].Digest.String()}, countEventsList(events, "blob "))

	require.NoError(t, Push(ctx, nil, "", img.cs, img.cs, img.manifest.Digest, ref, true, nil, false, nil, WithBlobUploader(u)))

	events, blobs, manifests := reg.snapshot()
	for dgst, n := range countEvents(events, "blob ") {
		require.Equal(t, 1, n, "blob %s uploaded %d times", dgst, n)
	}
	// Push does not even check the blobs that were uploaded early.
	for dgst, n := range countEvents(events, "check ") {
		require.Equal(t, 1, n, "blob %s checked %d times", dgst, n)
	}
	require.Equal(t, "manifest latest", events[len(events)-1], "manifest must be pushed last")

	_, plainBlobs, plainManifests := plainReg.snapshot()
	require.Equal(t, plainBlobs, blobs)
	require.Equal(t, plainManifests, manifests)
}

// TestPushRetriesFailedEarlyUpload checks that a blob whose early upload
// failed is uploaded by Push.
func TestPushRetriesFailedEarlyUpload(t *testing.T) {
	ctx := t.Context()
	img := newTestImage(t)

	reg, host := newTestRegistry(t)
	reg.failBlob = img.layers[1].Digest
	ref := host + "/test/img:latest"
	u, err := NewBlobUploader(ctx, nil, "", img.cs, img.cs, ref, true, nil)
	require.NoError(t, err)
	defer u.Close()
	for _, l := range img.layers {
		u.Upload(l)
	}
	require.NoError(t, Push(ctx, nil, "", img.cs, img.cs, img.manifest.Digest, ref, true, nil, false, nil, WithBlobUploader(u)))

	events, blobs, _ := reg.snapshot()
	require.Equal(t, 2, countEvents(events, "blob ")[img.layers[1].Digest.String()])
	for _, l := range img.layers {
		require.Contains(t, blobs, l.Digest)
	}
}

// TestPushWithBlobUploaderWrongRepository checks that an uploader for another
// repository is rejected.
func TestPushWithBlobUploaderWrongRepository(t *testing.T) {
	ctx := t.Context()
	img := newTestImage(t)
	_, host := newTestRegistry(t)
	u, err := NewBlobUploader(ctx, nil, "", img.cs, img.cs, host+"/test/other:latest", true, nil)
	require.NoError(t, err)
	defer u.Close()
	err = Push(ctx, nil, "", img.cs, img.cs, img.manifest.Digest, host+"/test/img:latest", true, nil, false, nil, WithBlobUploader(u))
	require.ErrorContains(t, err, "can't be used to push")
}
