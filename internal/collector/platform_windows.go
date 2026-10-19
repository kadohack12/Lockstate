//go:build windows

package collector

func collectPlatform(info *SystemInfo) error { return collectWindows(info) }
