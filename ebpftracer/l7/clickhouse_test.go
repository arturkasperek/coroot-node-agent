package l7

import (
	"encoding/binary"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Query packets one ClickHouse 26.9 server sent another for a distributed INSERT
// and SELECT, captured with strace in the dev cluster. The SELECT asks the shard
// for stage 4 (WithMergeableStateAfterAggregationAndLimit) and carries an empty
// list of current roles; a wrong revision read one of its settings as the query.
func TestParseClickhouseQueriesOfClickhouse26_9(t *testing.T) {
	for file, prefix := range map[string]string{
		"testdata/clickhouse_26.9_query_distributed_select.bin": "SELECT `__table1`.`Timestamp` AS `Timestamp` FROM `default`.`otel_logs`",
		"testdata/clickhouse_26.9_query_insert_otel_logs.bin":   "INSERT INTO default.otel_logs (Timestamp, TraceId, SpanId,",
		"testdata/clickhouse_26.9_query_insert_otel_traces.bin": "INSERT INTO default.otel_traces (Timestamp, TraceId, SpanId,",
	} {
		t.Run(file, func(t *testing.T) {
			payload, err := os.ReadFile(file)
			require.NoError(t, err)
			assert.Contains(t, ParseClickhouse(payload), prefix)
		})
	}
}

// chQueryWriter writes a Query packet the way ClickHouse does for a given
// protocol revision: Connection::sendQuery and ClientInfo::write.
type chQueryWriter struct {
	packet []byte
}

func (w *chQueryWriter) varint(v uint64) {
	w.packet = binary.AppendUvarint(w.packet, v)
}

func (w *chQueryWriter) str(s string) {
	w.varint(uint64(len(s)))
	w.packet = append(w.packet, s...)
}

func (w *chQueryWriter) byte(b byte) {
	w.packet = append(w.packet, b)
}

func chQueryPacket(revision uint64, iface byte, query string) []byte {
	w := &chQueryWriter{}
	w.byte(1)              // Query
	w.str("my-query-id-1") // query id
	// ClientInfo
	w.byte(1) // initial query
	w.str("default")
	w.str("my-query-id-1")
	w.str("10.42.0.40:9000")
	if revision >= 54449 {
		w.packet = append(w.packet, make([]byte, 8)...) // initial query start time
	}
	w.byte(iface)
	switch iface {
	case 1: // TCP
		w.str("os-user")
		w.str("client-host")
		w.str("ClickHouse client")
		w.varint(26)
		w.varint(9)
		w.varint(revision)
	case 2: // HTTP
		w.byte(1) // method
		w.str("curl/8.0")
		if revision >= 54443 {
			w.str("10.0.0.1") // forwarded for
		}
		if revision >= 54447 {
			w.str("http://referer")
		}
		if revision >= 54490 {
			w.str("query_handler")
			w.str("/?query=...")
		}
	}
	if revision >= 54060 {
		w.str("") // quota key
	}
	if revision >= 54448 {
		w.varint(0) // distributed depth
	}
	if iface == 1 && revision >= 54401 {
		w.varint(10) // client version patch
	}
	if revision >= 54442 { // OpenTelemetry context
		w.byte(1)
		w.packet = append(w.packet, make([]byte, 16+8)...)
		w.str("vendor=value")
		w.byte(1)
	}
	if revision >= 54453 { // parallel replicas
		w.varint(0)
		w.varint(0)
		w.varint(0)
	}
	if revision >= 54475 { // query and line numbers
		w.varint(2)
		w.varint(7)
	}
	if revision >= 54476 { // JWT
		w.byte(1)
		w.str("header.payload.signature")
	}
	if revision >= 54485 {
		w.str("clickhouse-client") // client agent
	}
	if revision >= 54486 {
		w.byte(0) // is internal
	}
	if revision >= 54488 { // current roles
		w.byte(1)
		w.varint(2)
		w.str("reader")
		w.str("writer")
	}
	// settings, as strings with flags
	w.str("send_logs_level")
	w.varint(1)
	w.str("none")
	w.str("")
	if revision >= 54472 {
		w.str("") // externally granted roles
	}
	if revision >= 54441 {
		w.str("") // interserver secret
	}
	w.varint(2) // stage: complete
	w.varint(1) // compression
	w.str(query)
	return w.packet
}

func TestParseClickhouseQueryOfEachRevisionAndInterface(t *testing.T) {
	const query = "SELECT count() FROM system.one"
	for _, revision := range []uint64{54449, 54460, 54475, 54494} {
		for iface, name := range map[byte]string{1: "TCP", 2: "HTTP", 9: "BACKGROUND"} {
			t.Run(fmt.Sprintf("%d %s", revision, name), func(t *testing.T) {
				assert.Equal(t, query, ParseClickhouse(chQueryPacket(revision, iface, query)))
			})
		}
	}
}
