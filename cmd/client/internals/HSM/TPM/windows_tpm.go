//go:build windows

package TPM

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)                                                                                                                                                                                                    
																																																	
func openTPM() (transport.TPMCloser, error) {
	return windowstpm.Open()
}