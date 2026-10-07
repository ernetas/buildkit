package compression

import "strconv"

// OutputKey names the bytes this config produces: two configs with the same
// key compress the same input to the same output. It lets a result computed
// once be reused instead of compressing again.
//
// The key carries the type, the level and, for zstd, the encoder mode. The
// mode matters because a parallel zstd encoder writes different bytes than the
// sequential one, while the number of parallel workers does not. Only the
// sequential encoder exists today; a parallel mode must change the key.
//
// ok is false for types whose output depends on more than the config, such as
// estargz with its TOC annotations; their results must not be reused this way.
func (c Config) OutputKey() (key string, ok bool) {
	level := "default"
	if c.Level != nil {
		level = strconv.Itoa(*c.Level)
	}
	switch c.Type {
	case Uncompressed:
		return Uncompressed.String(), true
	case Gzip:
		return Gzip.String() + "-" + level, true
	case Zstd:
		return Zstd.String() + "-" + level + "-sequential", true
	default:
		return "", false
	}
}
