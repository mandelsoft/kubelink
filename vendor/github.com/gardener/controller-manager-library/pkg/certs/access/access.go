/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package access

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/gardener/controller-manager-library/pkg/certmgmt"
	"github.com/gardener/controller-manager-library/pkg/certs"
	"github.com/gardener/controller-manager-library/pkg/logger"
)

type AccessSource struct {
	base certs.WatchableSource

	currentCert *tls.Certificate
	info        certmgmt.CertificateInfo
	config      *certmgmt.Config
	access      certmgmt.CertificateAccess
	logger      logger.LogContext
}

var _ certs.CertificateSource = &AccessSource{}

func New(ctx context.Context, logger logger.LogContext, access certmgmt.CertificateAccess, cfg *certmgmt.Config) (*AccessSource, error) {
	this := &AccessSource{
		config: cfg,
		access: access,
		logger: logger,
	}
	// Initial read of certificate and key.
	if err := this.ReadCertificate(); err != nil {
		return nil, err
	}

	this.start(ctx.Done())
	return this, nil
}

func (this *AccessSource) RegisterConsumer(h certs.CertificateConsumerUpdater) {
	this.base.RegisterConsumer(h)
}

func (this *AccessSource) ReadCertificate() error {
	info, err := this.access.Get(this.logger)
	if err != nil {
		return err
	}
	new, err := certmgmt.UpdateCertificate(info, this.config)
	if err != nil {
		return err
	}
	if this.currentCert != nil {
		if certmgmt.Equal(this.info, new) {
			return nil
		}
	}
	if !certmgmt.Equal(this.info, new) {
		err = this.access.Set(this.logger, new)
		if err != nil {
			return err
		}
	}
	this.info = new

	cert, err := tls.X509KeyPair(new.Cert(), new.Key())
	if err != nil {
		return err
	}

	this.base.Lock()
	this.currentCert = &cert
	this.base.Unlock()
	this.base.NotifyUpdate(new)
	return nil
}

// GetCertificate fetches the currently loaded certificate, which may be nil.
func (this *AccessSource) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	this.base.Lock()
	defer this.base.Unlock()
	return this.currentCert, nil
}

func (this *AccessSource) GetCertificateInfo() certmgmt.CertificateInfo {
	this.base.Lock()
	defer this.base.Unlock()
	return this.info
}

func (this *AccessSource) start(stop <-chan struct{}) {
	go this.watch(stop)
}

func (this *AccessSource) watch(stop <-chan struct{}) {
	d := this.config.Rest
	if d > 10*time.Minute {
		d = 10 * time.Minute
	}
	backoff := 1 * time.Second

	timer := time.NewTimer(d)
	for {
		select {
		case <-stop:
			timer.Stop()
			return
		case _, ok := <-timer.C:
			if !ok {
				return
			}
			this.logger.Errorf("reconciling certificate %s", this.access)
			next := d

			err := this.ReadCertificate()
			if err != nil {
				this.logger.Errorf("cannot reconcile certificate %s: %s (backoff=%s)", this.access, err, backoff)
				next = backoff
				backoff = backoff * 3 / 2
			} else {
				backoff = 1 * time.Second
			}
			timer.Reset(next)
		}
	}
}
