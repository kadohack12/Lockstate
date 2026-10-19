//go:build !linux && !windows

package collector

import (
	"fmt"
	"runtime"
)

// collectPlatform : aucun collecteur n'existe encore pour cet OS (macOS : voir la roadmap).
func collectPlatform(_ *SystemInfo) error {
	return fmt.Errorf("OS non supporté : %s", runtime.GOOS)
}
