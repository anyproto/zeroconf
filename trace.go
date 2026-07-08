package zeroconf

import (
	"fmt"
	"io"
	"os"
	"sync/atomic"
)

// #p2p trace sink.
//
// All #p2p debug output routes through tracef/traceln so the host app can
// redirect it to a file + HTTP endpoint by calling SetTraceWriter. The default
// sink is stdout (the device console), so behaviour is unchanged until the host
// overrides it.
//
// Throwaway debug instrumentation — remove alongside debugstats.go.

type traceWriterHolder struct{ w io.Writer }

var traceWriterValue atomic.Value // holds traceWriterHolder

// SetTraceWriter redirects all #p2p trace output to w (e.g. an
// io.MultiWriter(os.Stdout, file)). Pass nil to restore stdout.
func SetTraceWriter(w io.Writer) {
	traceWriterValue.Store(traceWriterHolder{w: w})
}

func traceOut() io.Writer {
	if v, ok := traceWriterValue.Load().(traceWriterHolder); ok && v.w != nil {
		return v.w
	}
	return os.Stdout
}

// tracef writes one preformatted line to the sink in a single Write call, so
// concurrent callers (recv4/recv6/client recv/sendQuery/...) never interleave
// mid-line as long as the sink's Write is atomic.
func tracef(format string, a ...interface{}) {
	io.WriteString(traceOut(), fmt.Sprintf(format, a...))
}

func traceln(a ...interface{}) {
	io.WriteString(traceOut(), fmt.Sprintln(a...))
}
