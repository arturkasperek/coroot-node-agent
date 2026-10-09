package tracing

import (
	"context"
	"sync"
	"sync/atomic"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// The SDK's BatchSpanProcessor bounds its queue by the number of spans only. A span with
// HTTP bodies carries up to two 4 KB bodies, so a queue of 16384 spans could hold ~130 MB
// while the collector was slow, on top of an agent that has 1 GiB in all. queueBudget
// bounds it by an estimate of the bytes too: a span is reserved when it ends, before the
// SDK queue, and given back when the exporter is done with it (sent or failed: the SDK does
// not retry). A span over the budget is dropped and counted.
//
// The number of spans stays bounded as well, at the capacity of the SDK queue: the SDK
// drops a span it has no room for silently, and its bytes would never be given back.
type queueBudget struct {
	maxBytes int64
	maxSpans int64

	mu      sync.Mutex
	bytes   atomic.Int64
	spans   atomic.Int64
	dropped atomic.Uint64
}

func newQueueBudget(maxBytes, maxSpans int64) *queueBudget {
	return &queueBudget{maxBytes: maxBytes, maxSpans: maxSpans}
}

func (b *queueBudget) reserve(s sdktrace.ReadOnlySpan) bool {
	size := spanSize(s)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.spans.Load()+1 > b.maxSpans || b.bytes.Load()+size > b.maxBytes {
		b.dropped.Add(1)
		return false
	}
	b.spans.Add(1)
	b.bytes.Add(size)
	return true
}

func (b *queueBudget) release(spans []sdktrace.ReadOnlySpan) {
	var size int64
	for _, s := range spans {
		size += spanSize(s)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.spans.Add(-int64(len(spans)))
	b.bytes.Add(-size)
}

// spanOverhead stands for what a span holds besides its name, attributes and events: the
// SDK's span structure, its ids and timestamps, the slices that hold the rest.
const spanOverhead = 512

// spanSize is an estimate of the memory of an ended span. It is a function of the span
// alone, so that what is given back is exactly what was reserved.
func spanSize(s sdktrace.ReadOnlySpan) int64 {
	size := int64(spanOverhead + len(s.Name()))
	size += attributesSize(s.Attributes())
	for _, e := range s.Events() {
		size += int64(len(e.Name)) + attributesSize(e.Attributes)
	}
	return size
}

func attributesSize(attrs []attribute.KeyValue) int64 {
	var size int64
	for _, kv := range attrs {
		size += int64(len(kv.Key))
		switch kv.Value.Type() {
		case attribute.STRING:
			size += int64(len(kv.Value.AsString()))
		case attribute.STRINGSLICE:
			for _, v := range kv.Value.AsStringSlice() {
				size += int64(len(v))
			}
		case attribute.BOOLSLICE:
			size += int64(len(kv.Value.AsBoolSlice()))
		case attribute.INT64SLICE:
			size += 8 * int64(len(kv.Value.AsInt64Slice()))
		case attribute.FLOAT64SLICE:
			size += 8 * int64(len(kv.Value.AsFloat64Slice()))
		default:
			size += 8
		}
	}
	return size
}

// budgetProcessor reserves the budget of a span before handing it to the batch processor.
type budgetProcessor struct {
	sdktrace.SpanProcessor
	budget *queueBudget
}

func (p budgetProcessor) OnEnd(s sdktrace.ReadOnlySpan) {
	if !s.SpanContext().IsSampled() {
		// the batch processor ignores it: nothing to reserve, nothing would be given back
		p.SpanProcessor.OnEnd(s)
		return
	}
	if !p.budget.reserve(s) {
		return
	}
	p.SpanProcessor.OnEnd(s)
}

// countingExporter counts what the OTLP exporter sent or failed to send, and gives the
// spans' budget back once it is done with them.
type countingExporter struct {
	sdktrace.SpanExporter
	budget *queueBudget
}

func (e countingExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	err := e.SpanExporter.ExportSpans(ctx, spans)
	if err != nil {
		spansExportFailed.Add(uint64(len(spans)))
	} else {
		spansExported.Add(uint64(len(spans)))
	}
	if e.budget != nil {
		e.budget.release(spans)
	}
	return err
}

// newBatcher is the span processor of the agent: a batch processor whose queue holds at
// most budget.maxSpans spans and budget.maxBytes bytes.
func newBatcher(exporter sdktrace.SpanExporter, budget *queueBudget) sdktrace.SpanProcessor {
	bsp := sdktrace.NewBatchSpanProcessor(countingExporter{SpanExporter: exporter, budget: budget},
		sdktrace.WithMaxQueueSize(int(budget.maxSpans)))
	return budgetProcessor{SpanProcessor: bsp, budget: budget}
}
