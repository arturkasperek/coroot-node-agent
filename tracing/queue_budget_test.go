package tracing

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// blockingExporter stands for a collector that does not answer: ExportSpans waits until
// unblock is called.
type blockingExporter struct {
	mu      sync.Mutex
	gate    chan struct{}
	spans   int
	failing bool
}

func newBlockingExporter() *blockingExporter { return &blockingExporter{gate: make(chan struct{})} }

func (e *blockingExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	<-e.gate
	e.mu.Lock()
	defer e.mu.Unlock()
	e.spans += len(spans)
	if e.failing {
		return errors.New("collector unavailable")
	}
	return nil
}

func (e *blockingExporter) Shutdown(context.Context) error { return nil }
func (e *blockingExporter) unblock()                       { close(e.gate) }
func (e *blockingExporter) exported() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.spans
}

func endSpans(tp *sdktrace.TracerProvider, n, bodyBytes int) {
	body := strings.Repeat("a", bodyBytes)
	for i := 0; i < n; i++ {
		_, s := tp.Tracer("test").Start(context.Background(), "POST /orders")
		s.SetAttributes(attribute.String("http.response.body", body))
		s.End()
	}
}

func budgetedProvider(t *testing.T, exp sdktrace.SpanExporter, budget *queueBudget) (*sdktrace.TracerProvider, sdktrace.SpanProcessor) {
	t.Helper()
	p := newBatcher(exp, budget)
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(p))
	return tp, p
}

// The queue in front of the exporter is bounded by the size of what it holds: a span with
// two 4 KB bodies weighs as much as dozens without, and counting spans let a burst of
// them hold ~130 MB while the collector was slow.
func TestQueueBudgetDropsSpansOverItsBytes(t *testing.T) {
	exp := newBlockingExporter()
	budget := newQueueBudget(100*1024, 10000)
	tp, p := budgetedProvider(t, exp, budget)

	endSpans(tp, 100, 10*1024)
	held := budget.spans.Load()
	assert.LessOrEqual(t, budget.bytes.Load(), int64(100*1024), "never more bytes than the budget")
	assert.Greater(t, held, int64(0))
	assert.Less(t, held, int64(10), "10 KB spans, 100 KB of budget")
	assert.Equal(t, uint64(100-held), budget.dropped.Load(), "every span over the budget is counted")

	exp.unblock()
	require.NoError(t, p.ForceFlush(context.Background()))
	assert.Equal(t, int(held), exp.exported(), "what was let in is exported: the SDK queue drops nothing on its own")
	assert.Zero(t, budget.bytes.Load(), "exported spans give their bytes back")
	assert.Zero(t, budget.spans.Load())

	endSpans(tp, 3, 10*1024)
	require.NoError(t, p.ForceFlush(context.Background()))
	assert.Equal(t, int(held)+3, exp.exported(), "after the queue drained, spans are let in again")
}

// The number of spans stays bounded too, at the capacity of the SDK queue: a span the
// SDK queue cannot take would be dropped silently and its bytes never given back.
func TestQueueBudgetBoundsTheNumberOfSpans(t *testing.T) {
	exp := newBlockingExporter()
	budget := newQueueBudget(1<<30, 50)
	tp, p := budgetedProvider(t, exp, budget)

	endSpans(tp, 200, 10)
	assert.Equal(t, int64(50), budget.spans.Load())
	assert.Equal(t, uint64(150), budget.dropped.Load())

	exp.unblock()
	require.NoError(t, p.ForceFlush(context.Background()))
	assert.Equal(t, 50, exp.exported())
	assert.Zero(t, budget.spans.Load())
	assert.Zero(t, budget.bytes.Load())
}

func TestQueueBudgetIsGivenBackWhenTheExportFails(t *testing.T) {
	exp := newBlockingExporter()
	exp.failing = true
	budget := newQueueBudget(1<<20, 1000)
	tp, p := budgetedProvider(t, exp, budget)

	endSpans(tp, 5, 1024)
	exp.unblock()
	_ = p.ForceFlush(context.Background())
	assert.Equal(t, 5, exp.exported())
	assert.Zero(t, budget.bytes.Load(), "a failed export frees the spans too: the SDK does not retry them")
	assert.Zero(t, budget.spans.Load())
}

// The SDK queue ignores spans that are not sampled: they must not take budget they would
// never give back.
func TestQueueBudgetIgnoresUnsampledSpans(t *testing.T) {
	exp := newBlockingExporter()
	budget := newQueueBudget(1<<20, 1000)
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(newBatcher(exp, budget)), sdktrace.WithSampler(sdktrace.NeverSample()))
	endSpans(tp, 10, 1024)
	assert.Zero(t, budget.bytes.Load())
	assert.Zero(t, budget.spans.Load())
	assert.Zero(t, budget.dropped.Load())
	exp.unblock()
}

func TestSpanSizeCountsTheBodies(t *testing.T) {
	exp := newBlockingExporter()
	budget := newQueueBudget(1<<20, 1000)
	tp, p := budgetedProvider(t, exp, budget)
	endSpans(tp, 1, 4096)
	size := budget.bytes.Load()
	assert.GreaterOrEqual(t, size, int64(4096), "the body is in the size")
	assert.Less(t, size, int64(4096+2048), "plus a bounded overhead for the rest of the span")
	exp.unblock()
	require.NoError(t, p.ForceFlush(context.Background()))
}
