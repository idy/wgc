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

func (v Verbose) PrintDepth(_ int, args ...interface{}) {
	if h := handler.Load(); h != nil {
		h.write(int(v.level), fmt.Sprint(args...))
	} else if v.level <= 0 {
		log.Print(args...)
	}
}

func (v Verbose) PrintfDepth(_ int, format string, args ...interface{}) {
	if h := handler.Load(); h != nil {
		h.write(int(v.level), fmt.Sprintf(format, args...))
	} else if v.level <= 0 {
		log.Printf(format, args...)
	}
}

func Warningf(format string, args ...interface{}) {
	V(-1).PrintfDepth(0, format, args...)
}

func Errorf(format string, args ...interface{}) {
	V(-2).PrintfDepth(0, format, args...)
}
