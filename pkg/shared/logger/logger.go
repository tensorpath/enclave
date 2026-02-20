package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type Level string

const (
	Info  Level = "INFO"
	Warn  Level = "WARN"
	Error Level = "ERROR"
	Debug Level = "DEBUG"
)

type Logger struct {
	mu  sync.Mutex
	out io.Writer
}

func New(w io.Writer) *Logger {
	return &Logger{out: w}
}

func (l *Logger) Log(level Level, msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry := struct {
		Time  string `json:"time"`
		Level Level  `json:"level"`
		Msg   string `json:"msg"`
	}{
		Time:  time.Now().Format(time.RFC3339),
		Level: level,
		Msg:   fmt.Sprintf(msg, args...),
	}

	json.NewEncoder(l.out).Encode(entry)
}

func (l *Logger) Info(msg string, args ...any) { l.Log(Info, msg, args...) }
func (l *Logger) Warn(msg string, args ...any) { l.Log(Warn, msg, args...) }
func (l *Logger) Error(msg string, args ...any) { l.Log(Error, msg, args...) }
func (l *Logger) Debug(msg string, args ...any) { l.Log(Debug, msg, args...) }

func (l *Logger) Fatal(msg string, args ...any) {
	l.Log(Error, msg, args...)
	os.Exit(1)
}

var Default = New(os.Stdout)
