package osutils

import (
	"fmt"
	"os"
	"runtime"
	"sync"
)

func GetCurrentBinPath() (string, error) {
	exePath, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return "", fmt.Errorf("unable to retrieve current exe: %v", err)
	}

	return exePath, nil
}

// GetIoDevice safely reads from the IoDevice struct
func (r *IoDevice) GetIoDevice() (string, uint32, uint32) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.MountPath, r.DeviceMajor, r.DeviceMinor
}

func IsLinux() bool {
	return runtime.GOOS == "linux"
}

// IoDevice holds basic information about a filesystem
type IoDevice struct {
	MountPath   string
	DeviceMajor uint32
	DeviceMinor uint32
	mu          sync.RWMutex
}

// NewIoDevice creates a new instance of IoDevice
func NewIoDevice(path string,
	major uint32,
	minor uint32) *IoDevice {

	// Initialize the IoDevice struct with the path, major and minor device info
	IoDevice := &IoDevice{
		MountPath:   path,
		DeviceMajor: major,
		DeviceMinor: minor,
	}

	return IoDevice
}

func FileExists(filename string) bool {
	_, err := os.Stat(filename)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	// Other errors may indicate the file doesn't exist
	return false
}
