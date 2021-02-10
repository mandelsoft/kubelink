/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package cert

import (
	"context"
	"fmt"
	"time"

	"github.com/gardener/controller-manager-library/pkg/certmgmt"
	certsecret "github.com/gardener/controller-manager-library/pkg/certmgmt/secret"
	"github.com/gardener/controller-manager-library/pkg/certs"
	"github.com/gardener/controller-manager-library/pkg/certs/access"
	"github.com/gardener/controller-manager-library/pkg/certs/file"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/cluster"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
)

func CreateSecretCertificateSource(ctx context.Context, logger logger.LogContext, cluster cluster.Interface, namespace string, cfg *CertConfig, keys ...certsecret.Keys) (certs.CertificateSource, error) {
	secret := certsecret.NewSecret(cluster, resources.NewObjectName(namespace, cfg.Secret), keys...)
	hosts := certmgmt.NewCompoundHosts()
	for _, h := range cfg.Hostnames {
		logger.Infof("using hostname for certificate: %s", h)
		hosts.Add(certmgmt.NewDNSName(h))
	}
	if cfg.Service != "" {
		logger.Infof("using service for certificate: %s/%s", cfg.Service, namespace)
		hosts.Add(certmgmt.NewServiceHosts(cfg.Service, namespace))
	}

	logger.Infof("using certificate for ips: %v, dns: %v", hosts.GetIPs(), hosts.GetDNSNames())

	var certcfg *certmgmt.Config
	if cfg.CommonName != "" {
		if len(hosts) == 0 {
			return nil, fmt.Errorf("hosts for managed certificate secret required")
		}
		logger.Infof("managing certificate")
		certcfg = &certmgmt.Config{
			CommonName:   cfg.CommonName,
			Organization: []string{cfg.Organization},
			Validity:     10 * 24 * time.Hour,
			Rest:         24 * time.Hour,
			Hosts:        hosts,
		}
	} else {
		logger.Infof("externally managed certificate")
	}
	return access.New(ctx, logger, secret, certcfg)
}

func CreateFileCertificateSource(ctx context.Context, logger logger.LogContext, cfg *CertConfig) (certs.CertificateSource, error) {
	return file.New(ctx, logger, cfg.CertFile, cfg.KeyFile, cfg.CACertFile, cfg.CAKeyFile)
}
