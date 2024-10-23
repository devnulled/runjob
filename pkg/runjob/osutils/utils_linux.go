//go:build linux

package osutils

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func SetHostname(hostname string) error {
	return unix.Sethostname([]byte(hostname))
}

func GetRootDevice() (*IoDevice, error) {

	var stat unix.Stat_t
	err := unix.Stat("/", &stat)
	if err != nil {
		return nil, fmt.Errorf("unable to auto-detect root filesystem and version: %w", err)
	}

	// Extract major and minor device numbers using bit shifts and masks
	major := uint32((stat.Dev >> 8) & 0xfff)                          // Extracting major number
	minor := uint32((stat.Dev & 0xff) | ((stat.Dev >> 12) & 0xfff00)) // Extracting minor number

	return NewIoDevice("/", major, minor), nil
}
