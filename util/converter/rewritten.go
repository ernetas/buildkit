package converter

import (
	"cmp"
	"context"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/pkg/labels"
	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/buildkit/identity"
	"github.com/moby/buildkit/util/bklog"
	digest "github.com/opencontainers/go-digest"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

// Rewriting the timestamps of a layer is a pure function of the source blob,
// the epoch and the compression output key, so its result is recorded on the
// source blob and reused by later exports instead of converting again.
//
// The record is a GC reference label on the source blob,
//
//	containerd.io/gc.ref.content.buildkit/rewritten/v1/<epoch>/<output key> = <digest>
//
// so the rewritten blob lives exactly as long as the blob it was made from. The
// version is bumped whenever the rewrite itself starts producing other bytes.
const (
	rewrittenLabelPrefix  = "containerd.io/gc.ref.content.buildkit/rewritten/"
	rewrittenLabelVersion = "v1"
)

// maxRewrittenVariants bounds the rewritten blobs kept per source blob. Each
// is about as large as the source, and a new epoch per commit would otherwise
// keep adding them for as long as the layer stays cached.
const maxRewrittenVariants = 4

func rewrittenBlobLabel(epoch time.Time, outputKey string) string {
	epoch = epoch.UTC()
	e := strconv.FormatInt(epoch.Unix(), 10)
	if ns := epoch.Nanosecond(); ns != 0 {
		e += "." + strconv.Itoa(ns)
	}
	return rewrittenLabelPrefix + rewrittenLabelVersion + "/" + e + "/" + outputKey
}

// rewrittenLabelEpoch returns the epoch seconds of a rewritten blob label, or
// MinInt64 if the label is from another version or cannot be parsed.
func rewrittenLabelEpoch(key string) int64 {
	rest, ok := strings.CutPrefix(key, rewrittenLabelPrefix+rewrittenLabelVersion+"/")
	if !ok {
		return math.MinInt64
	}
	e, _, _ := strings.Cut(rest, "/")
	e, _, _ = strings.Cut(e, ".")
	sec, err := strconv.ParseInt(e, 10, 64)
	if err != nil {
		return math.MinInt64
	}
	return sec
}

// RewrittenBlobs returns the blobs with rewritten timestamps that the labels of
// a source blob keep alive.
func RewrittenBlobs(labels map[string]string) []digest.Digest {
	var out []digest.Digest
	for k, v := range labels {
		if !strings.HasPrefix(k, rewrittenLabelPrefix) {
			continue
		}
		if dgst, err := digest.Parse(v); err == nil {
			out = append(out, dgst)
		}
	}
	return out
}

// lookupRewritten returns the descriptor an earlier conversion of desc
// returned, if the blob it produced is still in the store.
func (c *conversion) lookupRewritten(ctx context.Context, cs content.Store, desc ocispecs.Descriptor) (*ocispecs.Descriptor, bool) {
	info, err := cs.Info(ctx, desc.Digest)
	if err != nil {
		return nil, false
	}
	target, err := digest.Parse(info.Labels[c.rewrittenLabel])
	if err != nil {
		return nil, false
	}
	if len(c.immDiffIDs) > 0 {
		// A conversion returns the source unchanged when its diffID is
		// immutable, so the record applies only if the diffID is known.
		origDiffID := desc.Annotations[labels.LabelUncompressed]
		if origDiffID == "" {
			origDiffID = info.Labels[labels.LabelUncompressed]
		}
		if origDiffID == "" {
			return nil, false
		}
		if _, ok := c.immDiffIDs[digest.Digest(origDiffID)]; ok {
			return nil, false
		}
	}
	tInfo, err := cs.Info(ctx, target)
	if err != nil {
		return nil, false
	}
	diffID, err := digest.Parse(tInfo.Labels[labels.LabelUncompressed])
	if err != nil {
		return nil, false
	}
	// Add the blob to the caller's lease, as writing it would have, so that it
	// stays until the export is done even if its source stops holding it.
	// Opening a writer for an existing digest does that and fails.
	ref := "rewritten-" + target.Encoded() + "-" + identity.NewID()
	w, err := cs.Writer(ctx, content.WithRef(ref), content.WithDescriptor(ocispecs.Descriptor{Digest: target, Size: tInfo.Size}))
	if err == nil {
		w.Close()
		cs.Abort(ctx, ref)
		return nil, false
	} else if !cerrdefs.IsAlreadyExists(err) {
		return nil, false
	}
	bklog.G(ctx).WithField("blob", desc).WithField("target", target).Debugf("reusing blob with rewritten timestamps")

	newDesc := desc
	newDesc.MediaType = c.target.Type.MediaType()
	newDesc.Digest = tInfo.Digest
	newDesc.Size = tInfo.Size
	newDesc.Annotations = map[string]string{
		labels.LabelUncompressed: diffID.String(),
		labelRewrittenTimestamp:  strconv.FormatInt(c.rewriteTimestamp.UTC().Unix(), 10),
	}
	return &newDesc, true
}

// recordRewritten links the converted blob to its source, so the next
// conversion with the same epoch and output key finds it.
func (c *conversion) recordRewritten(ctx context.Context, cs content.Store, desc ocispecs.Descriptor, target content.Info, diffID digest.Digest) error {
	// The commit keeps the labels of a blob that already existed, which may
	// lack the diffID the lookup needs.
	if target.Labels[labels.LabelUncompressed] != diffID.String() {
		if _, err := cs.Update(ctx, content.Info{
			Digest: target.Digest,
			Labels: map[string]string{labels.LabelUncompressed: diffID.String()},
		}, "labels."+labels.LabelUncompressed); err != nil {
			return errors.Wrapf(err, "failed to label %s", target.Digest)
		}
	}

	info, err := cs.Info(ctx, desc.Digest)
	if err != nil {
		return err // e.g. a lazy source that is not in the store
	}
	if info.Labels[c.rewrittenLabel] == target.Digest.String() {
		return nil
	}
	upd := content.Info{
		Digest: desc.Digest,
		Labels: map[string]string{c.rewrittenLabel: target.Digest.String()},
	}
	fields := []string{"labels." + c.rewrittenLabel}
	var others []string
	for k, v := range info.Labels {
		if strings.HasPrefix(k, rewrittenLabelPrefix) && k != c.rewrittenLabel && v != "" {
			others = append(others, k)
		}
	}
	if len(others) >= maxRewrittenVariants {
		// Drop the oldest epochs; an empty value removes the label.
		slices.SortFunc(others, func(a, b string) int {
			return cmp.Or(cmp.Compare(rewrittenLabelEpoch(a), rewrittenLabelEpoch(b)), strings.Compare(a, b))
		})
		for _, k := range others[:len(others)-maxRewrittenVariants+1] {
			upd.Labels[k] = ""
			fields = append(fields, "labels."+k)
		}
	}
	_, err = cs.Update(ctx, upd, fields...)
	return err
}
