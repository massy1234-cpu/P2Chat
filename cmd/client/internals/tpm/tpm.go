package tpm

import (
	"runtime"
)

// Function that return if the application is running on macos,windows or linux system
func WhichOS() string {
	switch runtime.GOOS {
		case "linux":
			return "Linux"
		case "windows":
			return "Windows"
		case "darwin":
			return "macOS" 
		default:
			return "" // if is not one of these the application can't use TPM
    }
}

