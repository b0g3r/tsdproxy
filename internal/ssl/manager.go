// SPDX-FileCopyrightText: 2026 Dima Boger
// SPDX-License-Identifier: MIT

package ssl

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/almeidapaulopt/tsdproxy/internal/config"
	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"
)

// Manager manages SSL certificate lifecycle including loading and hot-reload
type Manager struct {
	config  config.SSLConfig
	tlsCert *tls.Certificate
	watcher *fsnotify.Watcher
	log     zerolog.Logger
	mu      sync.RWMutex
}

// NewManager creates a new SSL certificate manager
func NewManager(cfg config.SSLConfig, log zerolog.Logger) (*Manager, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("SSL is not enabled")
	}

	// Validate configuration
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, fmt.Errorf("both certFile and keyFile must be specified")
	}

	return &Manager{
		config: cfg,
		log:    log,
	}, nil
}

// Load loads or reloads the SSL certificate
func (m *Manager) Load() error {
	m.log.Info().Msg("loading SSL certificate")

	// Load certificate from files
	m.log.Debug().
		Str("certFile", m.config.CertFile).
		Str("keyFile", m.config.KeyFile).
		Msg("loading certificate from files")

	certPEM, keyPEM, err := LoadFromFiles(m.config.CertFile, m.config.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate from files: %w", err)
	}

	// Parse the certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Validate the certificate (check if it's expired)
	if len(cert.Certificate) > 0 {
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			m.log.Warn().Err(err).Msg("failed to parse certificate for validation")
		} else {
			now := time.Now()
			if now.Before(x509Cert.NotBefore) {
				return fmt.Errorf("certificate is not yet valid (valid from %s)", x509Cert.NotBefore)
			}
			if now.After(x509Cert.NotAfter) {
				return fmt.Errorf("certificate has expired (expired on %s)", x509Cert.NotAfter)
			}

			// Warn if certificate will expire soon (within 30 days)
			daysUntilExpiry := time.Until(x509Cert.NotAfter).Hours() / 24
			if daysUntilExpiry < 30 {
				m.log.Warn().
					Float64("daysRemaining", daysUntilExpiry).
					Time("expiryDate", x509Cert.NotAfter).
					Msg("certificate will expire soon")
			}

			m.log.Info().
				Str("subject", x509Cert.Subject.String()).
				Str("issuer", x509Cert.Issuer.CommonName).
				Time("notBefore", x509Cert.NotBefore).
				Time("notAfter", x509Cert.NotAfter).
				Strs("dnsNames", x509Cert.DNSNames).
				Msg("certificate loaded successfully")
		}
	}

	// Store the certificate
	m.mu.Lock()
	m.tlsCert = &cert
	m.mu.Unlock()

	m.log.Info().Msg("SSL certificate loaded successfully")
	return nil
}

// GetTLSConfig returns a TLS configuration using the managed certificate
func (m *Manager) GetTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.getCertificate,
		MinVersion:     tls.VersionTLS12,
	}
}

// getCertificate is a callback for tls.Config to retrieve the certificate
func (m *Manager) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.tlsCert == nil {
		return nil, fmt.Errorf("no certificate loaded")
	}

	return m.tlsCert, nil
}

// Watch starts watching the certificate file for changes and reloads automatically
func (m *Manager) Watch() error {
	if !m.config.WatchRenewals {
		return nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}
	m.watcher = watcher

	// Watch the directory containing the certificate files
	watchPath := filepath.Dir(m.config.CertFile)
	m.log.Info().Str("path", watchPath).Msg("watching directory for certificate changes")

	// Start watching in a goroutine
	go m.watchLoop()

	// Add the watch path
	if err := watcher.Add(watchPath); err != nil {
		return fmt.Errorf("failed to watch path %s: %w", watchPath, err)
	}

	return nil
}

// watchLoop runs the file watching loop
func (m *Manager) watchLoop() {
	// Debounce timer to avoid multiple reloads for rapid file changes
	var debounceTimer *time.Timer
	debounceDuration := 2 * time.Second

	for {
		select {
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}

			// Check if the event is for our certificate files
			isRelevant := event.Name == m.config.CertFile || event.Name == m.config.KeyFile
			if !isRelevant {
				continue
			}

			// Only reload on write or create events
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				m.log.Info().Str("file", event.Name).Msg("certificate file changed")

				// Debounce: reset timer if already running, otherwise start new timer
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				debounceTimer = time.AfterFunc(debounceDuration, func() {
					m.log.Info().Msg("reloading certificate after file change")
					if err := m.Load(); err != nil {
						m.log.Error().Err(err).Msg("failed to reload certificate")
					} else {
						m.log.Info().Msg("certificate reloaded successfully")
					}
				})
			}

		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			m.log.Error().Err(err).Msg("certificate watcher error")
		}
	}
}

// Close stops the certificate watcher and cleans up resources
func (m *Manager) Close() error {
	if m.watcher != nil {
		return m.watcher.Close()
	}
	return nil
}
