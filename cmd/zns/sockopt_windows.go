// +build windows

package main

import "syscall"

func setSockoptInt(fd uintptr, level, opt, value int) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), level, opt, value)
}