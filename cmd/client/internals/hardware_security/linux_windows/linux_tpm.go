//go:build linux

package linux_windows

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

func openTPM() (transport.TPMCloser, error) {
	return linuxtpm.Open("/dev/tpmrm0")
}