/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// taken from sigs.k8s.io/controller-runtime/pkg/webhook/internal/certwatcher/certwatcher.go

package file

import (
	"context"
	"crypto/tls"

	"gopkg.in/fsnotify.v1"

	"github.com/gardener/controller-manager-library/pkg/certmgmt"
	"github.com/gardener/controller-manager-library/pkg/certs"
	"github.com/gardener/controller-manager-library/pkg/logger"
)

// CertWatcher watches certificate and key files for changes.  When either file
// changes, it reads and parses both and calls an optional callback with the new
// certificate.
type CertWatcher struct {
	base   certs.WatchableSource
	logger logger.LogContext

	info        certmgmt.CertificateInfo
	currentCert *tls.Certificate
	watcher     *fsnotify.Watcher

	certPath   string
	keyPath    string
	cacertPath string
	cakeyPath  string
}

var _ certs.CertificateSource = &CertWatcher{}

// New returns a new CertWatcher watching the given certificate and key.
func New(ctx context.Context, logger logger.LogContext, certPath, keyPath, cacertPath, cakeyPath string) (*CertWatcher, error) {
	var err error

	cw := &CertWatcher{
		logger:     logger,
		certPath:   certPath,
		keyPath:    keyPath,
		cacertPath: cacertPath,
		cakeyPath:  cakeyPath,
	}

	// Initial read of certificate and key.
	if err := cw.ReadCertificate(); err != nil {
		return nil, err
	}

	cw.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	err = cw.start(ctx.Done())
	if err != nil {
		return nil, err
	}

	return cw, nil
}

// GetCertificate fetches the currently loaded certificate, which may be nil.
func (this *CertWatcher) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	this.base.Lock()
	defer this.base.Unlock()
	return this.currentCert, nil
}

func (this *CertWatcher) GetCertificateInfo() certmgmt.CertificateInfo {
	this.base.Lock()
	defer this.base.Unlock()
	return this.info
}

// Start starts the watch on the certificate and key files.
func (this *CertWatcher) start(stopCh <-chan struct{}) error {
	files := []string{this.certPath, this.keyPath, this.cacertPath, this.cakeyPath}

	for _, f := range files {
		if f != "" {
			if err := this.watcher.Add(f); err != nil {
				return err
			}
		}
	}

	go this.watch()

	go func() {
		// Block until the stop channel is closed.
		<-stopCh

		_ = this.watcher.Close()
	}()
	return nil
}

// Watch reads events from the watcher's channel and reacts to changes.
func (this *CertWatcher) watch() {
	this.logger.Info("Starting certificate watcher")
	for {
		select {
		case event, ok := <-this.watcher.Events:
			// Channel is closed.
			if !ok {
				return
			}

			this.handleEvent(event)

		case err, ok := <-this.watcher.Errors:
			// Channel is closed.
			if !ok {
				return
			}

			this.logger.Error(err, "certificate watch error")
		}
	}
}

// ReadCertificate reads the certificate and key files from disk, parses them,
// and updates the current certificate on the watcher.  If a callback is set, it
// is invoked with the new certificate.
func (this *CertWatcher) ReadCertificate() error {
	info, err := certmgmt.LoadCertInfo(this.certPath, this.keyPath, this.cacertPath, this.cakeyPath)
	if err != nil {
		return err
	}

	if !certmgmt.Equal(info, this.info) {
		cert, err := certmgmt.GetCertificate(info)
		if err != nil {
			return err
		}
		this.base.Lock()
		this.currentCert = &cert
		this.info = info
		this.base.Unlock()
		this.base.NotifyUpdate(this.info)
	}
	this.logger.Info("Updated current TLS certificate")

	return nil
}

func (this *CertWatcher) handleEvent(event fsnotify.Event) {
	// Only care about events which may modify the contents of the file.
	if !(isWrite(event) || isRemove(event) || isCreate(event)) {
		return
	}

	this.logger.Info("certificate event", "event", event)

	// If the file was removed, re-add the watch.
	if isRemove(event) {
		if err := this.watcher.Add(event.Name); err != nil {
			this.logger.Error(err, "error re-watching file")
		}
	}

	if err := this.ReadCertificate(); err != nil {
		this.logger.Error(err, "error re-reading certificate")
	}
}

func isWrite(event fsnotify.Event) bool {
	return event.Op&fsnotify.Write == fsnotify.Write
}

func isCreate(event fsnotify.Event) bool {
	return event.Op&fsnotify.Create == fsnotify.Create
}

func isRemove(event fsnotify.Event) bool {
	return event.Op&fsnotify.Remove == fsnotify.Remove
}
