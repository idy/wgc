package logger

import (
	"fmt"
	"log"
	"sync/atomic"
)

type Level int

type output struct {
	write func(int, string)
}

var handler atomic.Pointer[output]

func SetHandler(write func(int, string)) {
	if write == nil {
		handler.Store(nil)
		return
	}
	handler.Store(&output{write: write})
}

type Verbose struct {
	level Level
}

func V(level Level) Verbose { return Verbose{level: level} }

// PrintLazy formats a message only when its level is enabled. One handler
// snapshot governs both formatting and delivery, even if SetHandler runs during
// formatting. The formatter runs synchronously and is never retained.
func (v Verbose) PrintLazy(message func() string) {
	h := handler.Load()
	if h == nil && v.level > 0 {
		return
	}
	text := message()
	if h != nil {
		h.write(int(v.level), text)
	} else {
		log.Print(text)
	}
}

func (v Verbose) PrintDepth(_ int, args ...interface{}) {
	v.PrintLazy(func() string { return fmt.Sprint(args...) })
}

func (v Verbose) PrintfDepth(_ int, format string, args ...interface{}) {
	v.PrintLazy(func() string { return fmt.Sprintf(format, args...) })
}

func Warningf(format string, args ...interface{}) {
	V(-1).PrintfDepth(0, format, args...)
}

func Errorf(format string, args ...interface{}) {
	V(-2).PrintfDepth(0, format, args...)
}
