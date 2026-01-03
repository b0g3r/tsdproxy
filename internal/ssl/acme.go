// SPDX-FileCopyrightText: 2026 Dima Boger
// SPDX-License-Identifier: MIT

package ssl

import (
	"fmt"
	"os"
)

// LoadFromFiles loads certificate and key from separate PEM files
func LoadFromFiles(certFile, keyFile string) (certPEM, keyPEM []byte, err error) {
	certPEM, err = os.ReadFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	keyPEM, err = os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read key file: %w", err)
	}

	return certPEM, keyPEM, nil
}
