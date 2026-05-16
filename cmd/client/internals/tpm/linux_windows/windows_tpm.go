//go:build windows

package linux_windows

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)                                                                                                                                                                                                    
																																																	
func openTPM() (transport.TPMCloser, error) {
	return windowstpm.Open()
}