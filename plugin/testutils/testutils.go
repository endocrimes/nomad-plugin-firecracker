package testutils

import (
	"runtime"
	"syscall"
	"testing"
)

func KVMIsAvailable(t *testing.T) bool {
	// KVM is only available on linux
	if runtime.GOOS != "linux" {
		return false
	}

	// Try to open /dev/kvm as RW
	fd, err := syscall.Open("/dev/kvm", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		// We can't open /dev/kvm, therefore it's either not configured or we don't
		// have permission.
		return false
	}
	defer syscall.Close(fd)

	return true
}

// KVMCompatible skips tests if KVM is not present
func KVMCompatible(t *testing.T) {
	if !KVMIsAvailable(t) {
		t.Skip("KVM not available")
	}
}
