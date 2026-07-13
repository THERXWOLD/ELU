//go:build !windows

package format

import (
	"os"
)

// replaceFile replaces the file at source with the file at destination.
// This is a Unix-specific implementation.
func replaceFile(source, destination string) error {
	return os.Rename(source, destination)
}
