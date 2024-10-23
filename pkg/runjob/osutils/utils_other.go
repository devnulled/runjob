//go:build !linux

package osutils

func SetHostname(hostname string) error {
	return nil
}

func GetRootDevice() (*IoDevice, error) {
	return nil, nil
}
