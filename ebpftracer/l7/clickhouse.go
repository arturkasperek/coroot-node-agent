package l7

import (
	"bytes"
	"encoding/binary"
	"unicode"
	"unicode/utf8"
)

const (
	chInterfaceTCP  = 1
	chInterfaceHTTP = 2
	chMaxQuerySize  = 1024
)

// The protocol revisions at which the Query packet changed (Connection::sendQuery,
// ClientInfo::write), newest first. Which one a packet was written for is the
// revision the client and the server agreed on, which the packet does not carry
// (a TCP client's own revision is in it, but clickhouse-go sends 0 there). So each
// is tried in turn, and the first one the whole packet parses with wins.
// Settings are sent as strings since 54429; older packets are not parsed.
var chQueryRevisions = []uint64{
	54490, // HTTP handler name and request URL
	54488, // current roles
	54486, // internal query flag
	54485, // client agent
	54476, // JWT
	54475, // script query and line numbers
	54472, // externally granted roles
	54453, // parallel replicas
	54449, // initial query start time
	54448, // distributed depth
	54447, // HTTP referer
	54443, // X-Forwarded-For
	54442, // OpenTelemetry context
	54441, // inter-server secret
	54429, // settings as strings
}

type chReader struct {
	data []byte
	off  int
}

func (r *chReader) uvarint() (uint64, bool) {
	if r.off >= len(r.data) {
		return 0, false
	}
	v, n := binary.Uvarint(r.data[r.off:])
	if n <= 0 {
		return 0, false
	}
	r.off += n
	return v, true
}

func (r *chReader) byte() (byte, bool) {
	if r.off >= len(r.data) {
		return 0, false
	}
	b := r.data[r.off]
	r.off++
	return b, true
}

func (r *chReader) skip(n int) bool {
	if n < 0 || n > len(r.data)-r.off {
		return false
	}
	r.off += n
	return true
}

func (r *chReader) skipStr() bool {
	l, ok := r.uvarint()
	return ok && l <= uint64(len(r.data)-r.off) && r.skip(int(l))
}

func (r *chReader) skipStrings(n int) bool {
	for i := 0; i < n; i++ {
		if !r.skipStr() {
			return false
		}
	}
	return true
}

func (r *chReader) skipUvarints(n int) bool {
	for i := 0; i < n; i++ {
		if _, ok := r.uvarint(); !ok {
			return false
		}
	}
	return true
}

// ParseClickhouse returns the query text of a native-protocol Query packet.
func ParseClickhouse(payload []byte) string {
	for _, revision := range chQueryRevisions {
		if query, ok := parseClickhouseQuery(payload, revision); ok {
			return query
		}
	}
	return ""
}

// parseClickhouseQuery reads a Query packet written for the given protocol
// revision; ok is false when the packet does not fit that revision.
func parseClickhouseQuery(payload []byte, revision uint64) (string, bool) {
	r := &chReader{data: payload}
	if _, ok := r.byte(); !ok { // packet type (Query)
		return "", false
	}
	if !r.skipStr() { // query id
		return "", false
	}
	if !r.skipClientInfo(revision) {
		return "", false
	}
	if !r.skipSettings() {
		return "", false
	}
	if revision >= 54472 && !r.skipStr() { // externally granted roles
		return "", false
	}
	if revision >= 54441 && !r.skipStr() { // inter-server secret
		return "", false
	}
	// QueryProcessingStage: up to WithMergeableStateAfterAggregationAndLimit (4),
	// which a distributed SELECT asks its shards for
	if stage, ok := r.uvarint(); !ok || stage > 4 {
		return "", false
	}
	if compression, ok := r.uvarint(); !ok || compression > 1 {
		return "", false
	}
	return r.query()
}

// skipClientInfo skips what ClientInfo::write writes for the revision.
func (r *chReader) skipClientInfo(revision uint64) bool {
	if kind, ok := r.byte(); !ok || kind < 1 || kind > 2 { // initial or secondary query
		return false
	}
	if !r.skipStrings(3) { // initial user, initial query id, initial address
		return false
	}
	if revision >= 54449 && !r.skip(8) { // initial query start time
		return false
	}
	iface, ok := r.byte()
	if !ok {
		return false
	}
	switch iface {
	case chInterfaceTCP:
		if !r.skipStrings(3) { // os user, client hostname, client name
			return false
		}
		// client version major, minor, revision (some drivers send 0 for the
		// revision, so it does not tell which one the packet was written for)
		if !r.skipUvarints(3) {
			return false
		}
	case chInterfaceHTTP:
		if _, ok = r.byte(); !ok { // method
			return false
		}
		if !r.skipStr() { // user agent
			return false
		}
		if revision >= 54443 && !r.skipStr() { // X-Forwarded-For
			return false
		}
		if revision >= 54447 && !r.skipStr() { // referer
			return false
		}
		if revision >= 54490 && !r.skipStrings(2) { // handler name, request URL
			return false
		}
	}
	if !r.skipStr() { // quota key
		return false
	}
	if revision >= 54448 && !r.skipUvarints(1) { // distributed depth
		return false
	}
	if iface == chInterfaceTCP && !r.skipUvarints(1) { // client version patch
		return false
	}
	if revision >= 54442 {
		hasTrace, ok := r.byte() // OpenTelemetry context
		if !ok || hasTrace > 1 {
			return false
		}
		if hasTrace == 1 && !(r.skip(16+8) && r.skipStr() && r.skip(1)) { // trace id, span id, state, flags
			return false
		}
	}
	// collaborate with initiator, count of participating replicas, number of the current replica
	if revision >= 54453 && !r.skipUvarints(3) {
		return false
	}
	if revision >= 54475 && !r.skipUvarints(2) { // script query and line numbers
		return false
	}
	if revision >= 54476 {
		hasJWT, ok := r.byte()
		if !ok || hasJWT > 1 || (hasJWT == 1 && !r.skipStr()) {
			return false
		}
	}
	if revision >= 54485 && !r.skipStr() { // client agent
		return false
	}
	if revision >= 54486 {
		if internal, ok := r.byte(); !ok || internal > 1 {
			return false
		}
	}
	if revision >= 54488 {
		hasRoles, ok := r.byte() // current roles
		if !ok || hasRoles > 1 {
			return false
		}
		if hasRoles == 1 {
			count, ok := r.uvarint()
			if !ok || count > uint64(len(r.data)-r.off) || !r.skipStrings(int(count)) {
				return false
			}
		}
	}
	return true
}

// skipSettings skips settings written as strings with flags, up to the empty name
// that ends them. A name has to look like one, which is what rejects a wrong
// revision whose fields happened to parse up to here.
func (r *chReader) skipSettings() bool {
	for {
		l, ok := r.uvarint()
		if !ok || l > uint64(len(r.data)-r.off) {
			return false
		}
		if l == 0 {
			return true
		}
		for _, c := range r.data[r.off : r.off+int(l)] {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
				return false
			}
		}
		r.off += int(l)
		if _, ok = r.uvarint(); !ok { // flags
			return false
		}
		if !r.skipStr() { // value
			return false
		}
	}
}

func isControlInQuery(r rune) bool {
	return unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r'
}

// query reads the query text, the last field the packet has for us.
func (r *chReader) query() (string, bool) {
	l, ok := r.uvarint() // query size
	if !ok || r.off > len(r.data) {
		return "", false
	}
	query := r.data[r.off:]
	if uint64(len(query)) > l {
		query = query[:l]
	}
	if len(query) > chMaxQuerySize {
		query = query[:chMaxQuerySize]
	}
	truncated := uint64(len(query)) < l
	if truncated {
		// the last captured byte is not the query's; nor is a partial multi-byte
		// character before it
		query = query[:len(query)-1]
		for len(query) > 0 {
			if r, size := utf8.DecodeLastRune(query); r != utf8.RuneError || size > 1 {
				break
			}
			query = query[:len(query)-1]
		}
	}
	query = bytes.TrimSpace(query)
	if len(query) == 0 {
		return "", false
	}
	// not a real query: misclassified, corrupted, or read with the wrong revision
	if !utf8.Valid(query) || bytes.IndexFunc(query, isControlInQuery) >= 0 {
		return "", false
	}
	if truncated {
		return string(query) + "...<TRUNCATED>", true
	}
	return string(query), true
}
