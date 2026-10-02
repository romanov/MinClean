//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

var getConsoleProcessList = syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleProcessList")

// Explorer gives the app a console of its own. An existing terminal shares its
// console with the shell. Only pause in an interactive console we own, so pipes,
// redirected output, and terminal commands continue to finish normally.
func ownsInteractiveConsole() bool {
	var mode uint32
	if syscall.GetConsoleMode(syscall.Handle(os.Stdin.Fd()), &mode) != nil ||
		syscall.GetConsoleMode(syscall.Handle(os.Stdout.Fd()), &mode) != nil {
		return false
	}
	var processID uint32
	count, _, _ := getConsoleProcessList.Call(uintptr(unsafe.Pointer(&processID)), 1)
	return count == 1 && processID == uint32(os.Getpid())
}
