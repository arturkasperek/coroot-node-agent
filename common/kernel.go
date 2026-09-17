package common

import (
	"fmt"
)

var (
	kernelVersion    Version
	MinKernelVersion = NewVersion(6, 18, 0)
)

func SetKernelVersion(version string) error {
	v, err := VersionFromString(version)
	if err != nil || v.Major == 0 {
		return fmt.Errorf("invalid kernel version: %s", version)
	}
	kernelVersion = v
	return nil
}

func GetKernelVersion() Version {
	return kernelVersion
}

func CheckKernelVersion() error {
	if !GetKernelVersion().GreaterOrEqual(MinKernelVersion) {
		return fmt.Errorf("the minimum Linux kernel version required is %s or later", MinKernelVersion)
	}
	return nil
}
