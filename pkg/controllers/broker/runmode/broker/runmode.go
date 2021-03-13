/*
 * Copyright 2021 Mandelsoft. All rights reserved.
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
	"fmt"
	"io"
	"net"
	"time"

	"github.com/gardener/controller-manager-library/pkg/certmgmt"
	certsecret "github.com/gardener/controller-manager-library/pkg/certmgmt/secret"
	"github.com/gardener/controller-manager-library/pkg/certs"
	"github.com/gardener/controller-manager-library/pkg/certs/access"
	"github.com/gardener/controller-manager-library/pkg/certs/file"
	"github.com/gardener/controller-manager-library/pkg/ctxutil"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/controllers"
	"github.com/mandelsoft/kubelink/pkg/controllers/broker/config"
	"github.com/mandelsoft/kubelink/pkg/controllers/broker/runmode"
	"github.com/mandelsoft/kubelink/pkg/iptables"
	"github.com/mandelsoft/kubelink/pkg/kubelink"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

// TODO: switch to dedicated config for run mode

const DefaultPort = 80

type mode struct {
	runmode.RunModeBase
	config   *config.Config
	certInfo *CertInfo
	mux      *Mux

	finalizer func()
}

var _ runmode.RunMode = &mode{}

func NewBridgeMode(env runmode.RunModeEnv) (runmode.RunMode, error) {
	this := &mode{
		RunModeBase: runmode.NewRunModeBase(config.RUN_MODE_BRIDGE, env),
		config:      env.Config(),
	}
	if this.config.Port == 0 {
		this.config.Port = 8088
	}
	if this.config.Service != "" {
		this.Infof("using bridge service %q", this.config.Service)
	} else {
		this.Infof("using bridge port %d", this.config.Port)
	}
	return this, nil
}

func (this *mode) Setup() error {
	var err error
	var certificate certs.CertificateSource
	if this.config.CertFile != "" {
		certificate, err = this.CreateFileCertificateSource()
	} else {
		if this.config.Secret != "" {
			certificate, err = this.CreateSecretCertificateSource()
		}
	}
	if err != nil {
		return fmt.Errorf("cannot setup tls: %s", err)
	}

	if certificate != nil {
		if _, err := certificate.GetCertificate(nil); err != nil {
			return fmt.Errorf("no TLS certificate: %s", err)
		}
		this.certInfo = NewCertInfo(this.Controller(), certificate)
	}

	if this.config.Service != "" {
		// analyse and validate service
		port, err := controllers.GetServicePort(this.Controller(), this.config.Service, "bridge", corev1.ProtocolTCP)
		if err != nil {
			return err
		}
		this.config.Port = port
		this.Infof("using bridge port %d from service %q", port, this.config.Service)
	}

	tun, err := NewTun(this.Controller(), this.config.Interface)
	if err != nil {
		return fmt.Errorf("cannot setup tun device: %s", err)
	}

	var local tcp.CIDRList
	if this.config.ServiceCIDR != nil {
		local.Add(this.config.ServiceCIDR)
	}
	mux := NewMux(this.Controller().GetContext(), this.Controller(), this.certInfo, uint16(this.config.AdvertisedPort), local, tun, this.Links(), this)

	if this.config.DNSAdvertisement {
		mux.connectionHandler = &DefaultConnectionHandler{this}
	}

	this.mux = mux
	return nil
}

func (this *mode) Cleanup() error {
	if this.mux != nil && this.mux.tun != nil {
		this.mux.tun.Close()
	}
	if this.finalizer != nil {
		this.finalizer()
	}
	return nil
}

func (this *mode) Start() error {
	NewServer("broker", this.mux).Start(this.certInfo, "", this.config.Port)
	go func() {
		defer ctxutil.Cancel(this.Controller().GetContext())
		this.Controller().Infof("starting tun server")
		for {
			err := this.mux.HandleTun()
			if err != nil {
				if err == io.EOF {
					this.Controller().Errorf("tun server finished")
				} else {
					this.Controller().Errorf("tun handling aborted: %s", err)
				}
				break
			} else {
				this.mux.tun.Close()
				time.Sleep(100 * time.Millisecond)
				this.Controller().Infof("recreating tun device")
				this.mux.tun, err = NewTun(this.Controller(), this.config.Interface)
				if err != nil {
					panic(fmt.Errorf("cannot setup tun device: %s", err))
				}
			}
		}
	}()
	return nil
}

func (this *mode) HandleDNSPropagation(klink *api.KubeLink) {
	if this.config.DNSPropagation != config.DNSMODE_NONE && klink.Spec.Endpoint != kubelink.EP_LOCAL {
		this.Tasks().ScheduleTask(NewConnectTask(klink.Name, this), 0)
	}
}

func (this *mode) GetInterface() netlink.Link {
	return this.mux.tun.link
}

func (this *mode) UpdateLocalGatewayInfo(*controllers.LocalGatewayInfo) {
}

func (this *mode) GetErrorForMeshNode(ip net.IP) error {
	return this.mux.GetError(ip)
}

func (this *mode) RequiredIPTablesChains() iptables.Requests {
	return nil
}

func (this *mode) ReconcileInterface(logger logger.LogContext) error {
	var err error

	logger.Debug("update tun")

	addrs := this.Links().GetGatewayAddrs()
	natchains := this.Links().GetNatChains(addrs)
	this.finalizer, err = this.Env().LinkTool().PrepareLink(logger, this.mux.tun.link, addrs, natchains)

	if err != nil {
		logger.Errorf("%s", err)
	}
	return err
}

////////////////////////////////////////////////////////////////////////////////

func (this *mode) Notify(l *kubelink.Link, err error) {
	if err != nil {
		this.Controller().Infof("requeue kubelink %q for failure handling: %s", l.Name, err)
	} else {
		this.Controller().Infof("requeue kubelink %q for new connection", l.Name)
	}
	this.Controller().EnqueueKey(resources.NewClusterKey(this.Controller().GetMainCluster().GetId(), api.KUBELINK, "", l.Name))
}

func (this *mode) CreateSecretCertificateSource() (certs.CertificateSource, error) {
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
	case config.MANAGE_MODE_SELF:
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
	case config.MANAGE_MODE_CERT:
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

func (this *mode) CreateFileCertificateSource() (certs.CertificateSource, error) {
	cntr := this.Controller()
	return file.New(cntr.GetContext(), cntr, this.config.CertFile, this.config.KeyFile, this.config.CACertFile, "")
}
