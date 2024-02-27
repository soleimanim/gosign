package logger

import (
	"fmt"
	"os"

	"github.com/soleimanim/gosign/internal/cliargs"
)

type Logger struct {
	debugMode bool
}

func New() Logger {
	logger := Logger{}
	logger.debugMode = cliargs.IsDebugMode()

	return logger
}

func (l Logger) Debugf(format string, args ...any) {
	if l.debugMode {
		fmt.Printf(format, args...)
	}
}

func (l Logger) Debug(args ...any) {
	if l.debugMode {
		fmt.Print(args...)
	}
}

func (l Logger) Debugln(args ...any) {
	if l.debugMode {
		fmt.Println(args...)
	}
}

func (l Logger) Printf(format string, args ...any) {
	fmt.Printf(format, args...)
}

func (l Logger) Print(args ...any) {
	fmt.Print(args...)
}

func (l Logger) Println(args ...any) {
	fmt.Println(args...)
}

func (l Logger) Errorf(format string, args ...any) {
	fmt.Printf(format, args...)
}

func (l Logger) Error(args ...any) {
	fmt.Print(args...)
}

func (l Logger) Errorln(args ...any) {
	fmt.Println(args...)
}

func (l Logger) Fatalf(format string, args ...any) {
	fmt.Printf(format, args...)
	os.Exit(1)
}

func (l Logger) Fatal(args ...any) {
	fmt.Print(args...)
	os.Exit(1)
}

func (l Logger) Fatalln(args ...any) {
	fmt.Println(args...)
	os.Exit(1)
}
