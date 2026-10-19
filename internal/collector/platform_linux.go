//go:build linux

package collector

func collectPlatform(info *SystemInfo) error { return collectLinux(info) }
