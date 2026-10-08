package l7

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBodyAllowed(t *testing.T) {
	opts := DefaultBodyOptions()
	cases := []struct {
		ct, enc string
		body    string
		want    bool
	}{
		{"application/json", "", `{"a":1}`, true},
		{"application/json; charset=utf-8", "", `{"a":1}`, true},
		{"Application/JSON", "", `{"a":1}`, true},
		{"application/vnd.api+json", "", `{}`, true},
		{"text/plain", "", "hello", true},
		{"text/html; charset=iso-8859-1", "", "<p>", true},
		{"application/x-www-form-urlencoded", "", "a=1&b=2", true},
		{"application/json", "gzip", "\x1f\x8b", false},
		{"application/json", "identity", `{}`, true},
		{"application/json", "br", `{}`, false},
		{"application/grpc", "", "\x00\x00", false},
		{"application/grpc+proto", "", "\x00\x00", false},
		{"image/png", "", "\x89PNG", false},
		{"application/octet-stream", "", "abc", false},
		{"", "", `{"a":1}`, true},       // no content type: sniff the bytes
		{"", "", "\x00\x01\x02", false}, // binary
		{"", "", "\xff\xfe\xfd", false}, // not UTF-8
	}
	for _, c := range cases {
		assert.Equal(t, c.want, opts.Allowed(c.ct, c.enc, []byte(c.body)), "%+v", c)
	}
}

func TestBodyAllowedSniffToleratesCutRune(t *testing.T) {
	// a body cut in the middle of a multi-byte character is still text
	assert.True(t, DefaultBodyOptions().Allowed("", "", []byte("ab\xc4")))
}

func TestCutOnRuneBoundary(t *testing.T) {
	s := []byte("ab" + "ą") // 'ą' is 2 bytes
	assert.Equal(t, "ab", string(cutUTF8(s, 3)))
	assert.Equal(t, "abą", string(cutUTF8(s, 4)))
	assert.Equal(t, "abą", string(cutUTF8(s, 10)))
	assert.Equal(t, "ab", string(cutUTF8([]byte("ab\xc4"), 10)), "an incomplete tail is dropped even when nothing was cut")
	assert.Equal(t, "", string(cutUTF8(nil, 3)))
}

func TestBodyCollectorCaps(t *testing.T) {
	c := newBodyCollector(10)
	c.Add([]byte("hello"))
	assert.False(t, c.Full())
	c.Add([]byte("world!!!"))
	assert.Equal(t, "helloworld", string(c.Bytes()))
	assert.Equal(t, 10, c.Len())
	assert.True(t, c.Full())
	c.Add([]byte("more"))
	assert.Equal(t, "helloworld", string(c.Bytes()))
}

func TestParseContentLength(t *testing.T) {
	assert.Equal(t, int64(-1), parseContentLength(""))
	assert.Equal(t, int64(12), parseContentLength(" 12 "))
	assert.Equal(t, int64(-1), parseContentLength("abc"))
	assert.Equal(t, int64(-1), parseContentLength("-5"))
}
