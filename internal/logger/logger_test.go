package logger

import (
	"bytes"
	"fmt"
	"log"
	"slices"
	"testing"
)

func captureDefaultLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	writer, flags, prefix := log.Writer(), log.Flags(), log.Prefix()
	var out bytes.Buffer
	log.SetOutput(&out)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		SetHandler(nil)
		log.SetOutput(writer)
		log.SetFlags(flags)
		log.SetPrefix(prefix)
	})
	return &out
}

func TestPrintLazySuppressed(t *testing.T) {
	SetHandler(nil)
	for _, level := range []Level{1, 3} {
		V(level).PrintLazy(func() string {
			t.Fatal("suppressed message was formatted")
			return ""
		})
	}
}

func TestLoggerLevelsAndFormatting(t *testing.T) {
	out := captureDefaultLog(t)
	for _, level := range []Level{-2, -1, 0, 1, 3} {
		t.Run(fmt.Sprint(level), func(t *testing.T) {
			emit := func() {
				V(level).PrintDepth(0, "a", "b", 7)
				V(level).PrintfDepth(0, "%s=%d", "count", 2)
				V(level).PrintLazy(func() string { return "lazy" })
			}
			SetHandler(nil)
			out.Reset()
			emit()
			want := ""
			if level <= 0 {
				want = "ab7\ncount=2\nlazy\n"
			}
			if got := out.String(); got != want {
				t.Fatalf("default output = %q, want %q", got, want)
			}

			var messages []string
			SetHandler(func(gotLevel int, message string) {
				if gotLevel != int(level) {
					t.Errorf("level = %d, want %d", gotLevel, level)
				}
				messages = append(messages, message)
			})
			emit()
			wantMessages := []string{"ab7", "count=2", "lazy"}
			if !slices.Equal(messages, wantMessages) {
				t.Fatalf("handler messages = %q, want %q", messages, wantMessages)
			}
		})
	}
}

func TestPrintLazyHandlerSnapshot(t *testing.T) {
	t.Cleanup(func() { SetHandler(nil) })
	for _, clear := range []bool{false, true} {
		t.Run(fmt.Sprintf("clear=%t", clear), func(t *testing.T) {
			var first, second int
			SetHandler(func(_ int, _ string) { first++ })
			formatting, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			go func() {
				defer close(done)
				V(3).PrintLazy(func() string {
					close(formatting)
					<-resume
					return "message"
				})
			}()
			<-formatting
			if clear {
				SetHandler(nil)
			} else {
				SetHandler(func(_ int, _ string) { second++ })
			}
			close(resume)
			<-done
			if first != 1 || second != 0 {
				t.Fatalf("handler calls = (%d, %d), want (1, 0)", first, second)
			}
		})
	}
}

func TestPrintLazyDefaultSnapshot(t *testing.T) {
	out := captureDefaultLog(t)
	SetHandler(nil)
	formatting, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		V(0).PrintLazy(func() string {
			close(formatting)
			<-resume
			return "default message"
		})
	}()
	<-formatting
	var calls int
	SetHandler(func(_ int, _ string) { calls++ })
	close(resume)
	<-done
	if got := out.String(); got != "default message\n" || calls != 0 {
		t.Fatalf("default output = %q, handler calls = %d", got, calls)
	}
}
