/*
 * Copyright 2020 Mandelsoft. All rights reserved.
 *  This file is licensed under the Apache Software License, v. 2 except as noted
 *  otherwise in the LICENSE file
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package broker

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gardener/controller-manager-library/pkg/certmgmt"
	certsecret "github.com/gardener/controller-manager-library/pkg/certmgmt/secret"
	"github.com/gardener/controller-manager-library/pkg/certs"
	"github.com/gardener/controller-manager-library/pkg/certs/access"
	"github.com/gardener/controller-manager-library/pkg/certs/file"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type CertInfo struct {
	lock  sync.RWMutex
	roots *x509.CertPool
	certs.CertificateSource
}

func NewCertInfo(logger logger.LogContext, source certs.CertificateSource) *CertInfo {
	i := &CertInfo{
		CertificateSource: source,
	}
	if w, ok := source.(certs.Watchable); ok {
		logger.Infof("server certificate is watchable -> register change notification")
		w.RegisterConsumer(certs.CertificateUpdaterFunc(func(info certmgmt.CertificateInfo) {
			i.certificateUpdated()
		}))
	}
	i.certificateUpdated()
	return i
}

func (this *CertInfo) UseTLS() bool {
	return this != nil && this.CertificateSource != nil
}

func (this *CertInfo) Dial(endpoint string) (net.Conn, error) {
	if this.UseTLS() {
		return tls.Dial("tcp", endpoint, this.ClientConfig())
	} else {
		return net.Dial("tcp", endpoint)
	}
}

func (this *CertInfo) certificateUpdated() {
	if !this.UseTLS() {
		return
	}
	this.lock.Lock()
	defer this.lock.Unlock()

	info := this.GetCertificateInfo()
	if info == nil {
		panic(fmt.Errorf("no cert for client validation"))
	}

	this.roots = x509.NewCertPool()
	ok := this.roots.AppendCertsFromPEM(info.CACert())
	if !ok {
		panic(fmt.Errorf("failed to parse root certificate"))
	}
}

func (this *CertInfo) serverClientConfig(_ *tls.ClientHelloInfo) (*tls.Config, error) {
	if !this.UseTLS() {
		return nil, nil
	}
	this.lock.RLock()
	defer this.lock.RUnlock()
	return &tls.Config{
		NextProtos:     []string{"h2"},
		GetCertificate: this.GetCertificate,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      this.roots,
	}, nil
}

func (this *CertInfo) ServerConfig() *tls.Config {
	if !this.UseTLS() {
		return nil
	}
	return &tls.Config{
		NextProtos:         []string{"h2"},
		GetCertificate:     this.GetCertificate,
		GetConfigForClient: this.serverClientConfig,
		ClientAuth:         tls.RequireAndVerifyClientCert,
	}
}

func (this *CertInfo) ClientConfig() *tls.Config {
	if !this.UseTLS() {
		return nil
	}

	cert, err := this.GetCertificate(nil)
	if err != nil {
		logger.Errorf("cannot get client cert: %s", err)
		return nil
	}

	this.lock.RLock()
	defer this.lock.RUnlock()

	logger.Infof("dialing with client cert [%v]", this.roots)
	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		RootCAs:      this.roots,
	}
}

////////////////////////////////////////////////////////////////////////////////

func (this *reconciler) CreateSecretCertificateSource() (certs.CertificateSource, error) {
	cntr := this.Controller()
	namespace := cntr.GetEnvironment().Namespace()
	cluster := cntr.GetMainCluster()
	secret := certsecret.NewSecret(cluster, resources.NewObjectName(namespace, this.config.Secret), certsecret.TLSKeys())

	this.Controller().Infof("TLS secret is %s", secret)
	hosts := certmgmt.NewCompoundHosts()
	certcfg := &certmgmt.Config{
		CommonName:        this.config.DNSName,
		Organization:      []string{"gardener.cloud"},
		Validity:          10 * 24 * time.Hour,
		Rest:              24 * time.Hour,
		Hosts:             hosts,
		ExternallyManaged: true,
	}

	switch this.config.ManageMode {
	case MANAGE_MODE_SELF:
		if this.config.DNSName != "" {
			cntr.Infof("using hostname for certificate: %s", this.config.DNSName)
			hosts.Add(certmgmt.NewDNSName(this.config.DNSName))
		}
		if this.config.Service != "" {
			cntr.Infof("using service for certificate: %s/%s", this.config.Service, namespace)
			hosts.Add(certmgmt.NewServiceHosts(this.config.Service, namespace))
		}
		certcfg.ExternallyManaged = false
		cntr.Infof("using certificate for ips: %v, dns: %v", hosts.GetIPs(), hosts.GetDNSNames())
	case MANAGE_MODE_CERT:
		template := `
apiVersion: cert.gardener.cloud/v1alpha1
kind: Certificate
metadata:
  name: %s
  namespace: %s
spec:
  commonName: %s
  secretName: %s
`
		c := &unstructured.Unstructured{}
		c.UnmarshalJSON([]byte(fmt.Sprintf(template, this.config.Secret, namespace, this.config.DNSName, this.config.Secret)))

		_, err := cluster.Resources().CreateOrUpdateObject(c)
		if err != nil {
			return nil, err
		}
	}

	return access.New(cntr.GetContext(), cntr, secret, certcfg)
}

func (this *reconciler) CreateFileCertificateSource() (certs.CertificateSource, error) {
	cntr := this.Controller()
	return file.New(cntr.GetContext(), cntr, this.config.CertFile, this.config.KeyFile, this.config.CACertFile, "")
}
