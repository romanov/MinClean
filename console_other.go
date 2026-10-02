//go:build !windows

package main

func ownsInteractiveConsole() bool { return false }
