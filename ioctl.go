package gocryptodev

import "os"
import "unsafe"
import "syscall"

//A simple ioctl wrapper
func ioctl(file *os.File, op uintptr, data unsafe.Pointer) error {
    return ioctl2(file, op, uintptr(data))
}

//A simple ioctl wrapper which turns syscall errors into idiomatic
//go errors
func ioctl2(file *os.File, op uintptr, data uintptr) error {
    result, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
        file.Fd(), op, data)
    if errno != 0 || result != 0 {
        err := os.NewSyscallError("SYS_IOCTL", errno)
        return err
    }
    return nil
}
