package cachedigest

import (
	"crypto/sha256"
	"fmt"
	"testing"

	digest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
)

func TestNewHashWithoutDBRecordsNoFrames(t *testing.T) {
	d := &DB{}
	h := d.NewHash(TypeFileList)
	_, err := h.Write([]byte("foo"))
	require.NoError(t, err)
	_, err = h.WriteNoDebug([]byte("bar"))
	require.NoError(t, err)
	require.Empty(t, h.frames)
	require.Equal(t, digest.FromBytes([]byte("foobar")), h.Sum())

	dgst, err := d.FromBytes([]byte("hello"), TypeString)
	require.NoError(t, err)
	require.Equal(t, digest.FromBytes([]byte("hello")), dgst)
}

// TestDefaultDBRecordsFrames checks that the package-level helpers still
// record debug frames once a debug DB has been set with SetDefaultDB, which is
// what buildkitd does for --save-cache-debug.
func TestDefaultDBRecordsFrames(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	h := NewHash(TypeFileList)
	_, err := h.Write([]byte("foo"))
	require.NoError(t, err)
	_, err = h.WriteNoDebug([]byte("xyz"))
	require.NoError(t, err)
	sum := h.Sum()
	require.Equal(t, digest.FromBytes([]byte("fooxyz")), sum)

	dgst, err := FromBytes([]byte("hello"), TypeString)
	require.NoError(t, err)

	db.Wait()

	typ, frames, err := db.Get(t.Context(), sum.String())
	require.NoError(t, err)
	require.Equal(t, TypeFileList, typ)
	require.Equal(t, []Frame{
		{ID: FrameIDData, Data: []byte("foo")},
		{ID: FrameIDSkip, Data: []byte{3, 0, 0, 0}},
	}, frames)

	typ, frames, err = db.Get(t.Context(), dgst.String())
	require.NoError(t, err)
	require.Equal(t, TypeString, typ)
	require.Equal(t, []Frame{{ID: FrameIDData, Data: []byte("hello")}}, frames)
}

// BenchmarkHashFileList mimics hashing a directory with 5000 entries in
// cache/contenthash: every entry writes its name and its digest.
func BenchmarkHashFileList(b *testing.B) {
	const n = 5000
	names := make([][]byte, n)
	dgsts := make([][]byte, n)
	for i := range n {
		names[i] = fmt.Appendf(nil, "\x00file-%05d.txt", i)
		dgsts[i] = []byte(digest.FromBytes(names[i]).String())
	}
	run := func(b *testing.B, newHash func() *Hash) {
		b.ReportAllocs()
		for b.Loop() {
			h := newHash()
			for i := range n {
				h.Write(names[i])
				h.Write(dgsts[i])
			}
			_ = h.Sum()
		}
	}
	b.Run("default", func(b *testing.B) {
		run(b, func() *Hash { return NewHash(TypeFileList) })
	})
	b.Run("sha256", func(b *testing.B) {
		run(b, func() *Hash { return &Hash{h: sha256.New(), typ: TypeFileList} })
	})
}
