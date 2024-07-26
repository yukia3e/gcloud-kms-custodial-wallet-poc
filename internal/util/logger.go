package util

import (
	"fmt"
	"path/filepath"
	"runtime"
)

func WrapErrorForLog(packageName string, funcName string, err error) error {
	return fmt.Errorf("%s.%s: %w", packageName, funcName, err)
}

func WrapLogMessage(packageName, funcName, message string) string {
	return fmt.Sprintf("%s.%s: %s", packageName, funcName, message)
}

func FuncName() string {
	pc, _, _, _ := runtime.Caller(1)
	fullFuncName := runtime.FuncForPC(pc).Name()
	funcName := filepath.Ext(fullFuncName)
	return funcName[1:]
}
