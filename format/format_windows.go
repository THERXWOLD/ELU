//go:build windows

package format

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// replaceFile replaces the file at source with the file at destination.
// This is a Windows-specific implementation.
func replaceFile(source, destination string) error {
	sourcePtr, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return fmt.Errorf("encode source path: %w", err)
	}

	destinationPtr, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return fmt.Errorf("encode destination path: %w", err)
	}

	flags := uint32(
		windows.MOVEFILE_REPLACE_EXISTING |
			windows.MOVEFILE_WRITE_THROUGH,
	)

	if err := windows.MoveFileEx(sourcePtr, destinationPtr, flags); err != nil {
		return fmt.Errorf("MoveFileEx: %w", err)
	}

	return nil
}
