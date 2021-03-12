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

package config

import (
	"fmt"
	"net"
	"strings"

	"github.com/gardener/controller-manager-library/pkg/config"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/gardener/controller-manager-library/pkg/utils"

	"github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/controllers"
	"github.com/mandelsoft/kubelink/pkg/kubelink"

	//"github.com/mandelsoft/kubelink/pkg/kubelink"
	"github.com/mandelsoft/kubelink/pkg/tcp"
	kutils "github.com/mandelsoft/kubelink/pkg/utils"
)

const MANAGE_MODE_NONE = "none"
const MANAGE_MODE_SELF = "self"
const MANAGE_MODE_CERT = "cert"

const RUN_MODE_NONE = "none"
const RUN_MODE_BRIDGE = "bridge"
const RUN_MODE_WIREGUARD = "wireguard"

const CLUSTER_DNS_IP = 10
const KUBELINK_DNS_IP = 11

const DNSMODE_NONE = kubelink.DNSMODE_NONE
const DNSMODE_KUBERNETES = kubelink.DNSMODE_KUBERNETES
const DNSMODE_DNS = kubelink.DNSMODE_DNS

var valid_modes = utils.NewStringSet(MANAGE_MODE_NONE, MANAGE_MODE_SELF, MANAGE_MODE_CERT)

type Config struct {
	controllers.Config

	address     string
	service     string
	responsible string

	ClusterAddress *net.IPNet
	ClusterCIDR    *net.IPNet
	ClusterName    string

	ServiceCIDR *net.IPNet

	Responsible    utils.StringSet
	Port           int
	AdvertisedPort int

	CertFile   string
	KeyFile    string
	CACertFile string

	Secret     string
	ManageMode string
	DNSName    string
	Service    string
	Interface  string
	MeshDomain string

	serviceAccount   string
	ServiceAccount   resources.ObjectName
	DNSAdvertisement bool

	DNSPropagation    string
	coreDNSServiceIP  string
	CoreDNSServiceIP  net.IP
	CoreDNSDeployment string
	CoreDNSSecret     string
	CoreDNSConfigure  bool

	meshDNSServiceIP string
	MeshDNSServiceIP net.IP

	dnsServiceIP  string
	DNSServiceIP  net.IP
	ClusterDomain string

	AutoConnect bool
	Mode        string
}

func (this *Config) AddOptionsToSet(set config.OptionSet) {
	this.Config.AddOptionsToSet(set)
	set.AddStringOption(&this.service, "service-cidr", "", "", "CIDR of local service network")
	set.AddStringOption(&this.address, "link-address", "", "", "CIDR of cluster in cluster network")
	set.AddStringOption(&this.responsible, "served-links", "", "all", "Comma separated list of links to serve")
	set.AddIntOption(&this.Port, "broker-port", "", 0, "Port for bridge/wrireguard")
	set.AddIntOption(&this.AdvertisedPort, "advertised-port", "", kubelink.DEFAULT_PORT, "Advertised broker port for auto-connect")
	set.AddStringOption(&this.CertFile, "certfile", "", "", "TLS certificate file")
	set.AddStringOption(&this.KeyFile, "keyfile", "", "", "TLS certificate key file")
	set.AddStringOption(&this.CACertFile, "cacertfile", "", "", "TLS ca certificate file")
	set.AddStringOption(&this.Secret, "secret", "", "", "TLS or wireguard secret")
	set.AddStringOption(&this.Mode, "mode", "", RUN_MODE_BRIDGE, "VPN mode (bridge, wireguard, none)")
	set.AddStringOption(&this.ManageMode, "secret-manage-mode", "", MANAGE_MODE_NONE, "Manage mode for TLS secret")
	set.AddStringOption(&this.DNSName, "dns-name", "", "", "DNS Name for managed certificate")
	set.AddStringOption(&this.Service, "service", "", "", "Service name for wireguard or managed certificate")
	set.AddStringOption(&this.Interface, "ifce-name", "", "", "Name of the tun/wireguard interface")

	set.AddStringOption(&this.MeshDomain, "mesh-domain", "", "kubelink", "Default Base domain for cluster mesh services")
	set.AddStringOption(&this.meshDNSServiceIP, "meshdns-service-ip", "", "", "Default Service IP of global mesh service DNS service")
	set.AddStringOption(&this.ClusterName, "cluster-name", "", "", "Default Name of local cluster in cluster mesh")

	set.AddStringOption(&this.serviceAccount, "service-account", "", "", "Service Account for API Access propagation")

	set.AddBoolOption(&this.DNSAdvertisement, "dns-advertisement", "", false, "Enable automatic advertisement of DNS access info")
	set.AddStringOption(&this.dnsServiceIP, "dns-service-ip", "", "", "IP of Cluster DNS Service (for DNS Info Propagation)")
	set.AddStringOption(&this.ClusterDomain, "cluster-domain", "", "cluster.local", "Cluster Domain of Cluster DNS Service (for DNS Info Propagation)")

	set.AddStringOption(&this.DNSPropagation, "dns-propagation", "", "none", "Mode for accessing foreign DNS information (none, dns or kubernetes)")
	set.AddStringOption(&this.coreDNSServiceIP, "coredns-service-ip", "", "", "Service IP of coredns deployment used by kubelink")
	set.AddStringOption(&this.CoreDNSDeployment, "coredns-deployment", "", "kubelink-coredns", "Name of coredns deployment used by kubelink")
	set.AddStringOption(&this.CoreDNSSecret, "coredns-secret", "", "kubelink-coredns", "Name of dns secret used by kubelink")
	set.AddBoolOption(&this.CoreDNSConfigure, "coredns-configure", "", false, "Enable automatic configuration of cluster DNS (coredns)")
	set.AddBoolOption(&this.AutoConnect, "auto-connect", "", false, "Automatically register cluster for authenticated incoming requests")
}

func (this *Config) Prepare() error {
	err := this.Config.Prepare()
	if err != nil {
		return err
	}

	ip, cidr, err := this.RequireCIDR(this.address, "link-address")
	if err != nil {
		return err
	}
	this.ClusterCIDR = cidr
	this.ClusterAddress = tcp.CIDRIP(cidr, ip)

	_, this.ServiceCIDR, err = this.OptionalCIDR(this.service, "service-cidr")
	if err != nil {
		return err
	}

	if this.AutoConnect {
		if this.ServiceCIDR == nil {
			return fmt.Errorf("auto-connect requires local service cidr")
		}
		if kutils.Empty(this.Secret) && kutils.Empty(this.CertFile) {
			return fmt.Errorf("auto-connect requires authenticated mode -> secret or cert file requied")
		}
	}

	this.Responsible = utils.StringSet{}
	for _, l := range strings.Split(this.responsible, ",") {
		l = strings.TrimSpace(l)
		this.Responsible.Add(l)
	}
	if this.Responsible.Contains("all") {
		this.Responsible = utils.NewStringSet("all")
	}
	/*
		if Empty(this.CertFile) && Empty(this.Secret) {
			return fmt.Errorf("TLS secret or cert file must be set")
		}
	*/
	if !kutils.Empty(this.Secret) && !kutils.Empty(this.CertFile) {
		return fmt.Errorf("only secret or cert file can be specified")
	}
	if !kutils.Empty(this.ManageMode) {
		if !valid_modes.Contains(this.ManageMode) {
			return fmt.Errorf("invalid management mode (possible %s): %s", valid_modes, this.ManageMode)
		}
		if this.ManageMode == MANAGE_MODE_SELF {
			if this.DNSName == "" {
				return fmt.Errorf("dns name required for managed TLS secret")
			}
		}
	} else {
		this.ManageMode = MANAGE_MODE_NONE
	}
	if !kutils.Empty(this.CertFile) {
		if kutils.Empty(this.KeyFile) {
			return fmt.Errorf("key file must be specified if cert file is set")
		}
		if kutils.Empty(this.CACertFile) {
			return fmt.Errorf("ca cert file must be specified if cert file is set")
		}
	}

	if this.serviceAccount != "" {
		names := strings.Split(this.serviceAccount, "/")
		if len(names) > 2 {
			return fmt.Errorf("invalid service account name")
		}
		if len(names) == 2 {
			this.ServiceAccount = resources.NewObjectName(names...)
		} else {
			this.ServiceAccount = resources.NewObjectName("kube-system", names[0])
		}
	}

	if this.coreDNSServiceIP != "" {
		this.CoreDNSServiceIP = net.ParseIP(this.coreDNSServiceIP)
		if this.CoreDNSServiceIP == nil {
			return fmt.Errorf("invalid ip of coredns service: %s", this.coreDNSServiceIP)
		}
	}

	if this.meshDNSServiceIP != "" {
		this.MeshDNSServiceIP = net.ParseIP(this.meshDNSServiceIP)
		if this.MeshDNSServiceIP == nil {
			return fmt.Errorf("invalid ip of global mesh DNS service: %s", this.meshDNSServiceIP)
		}
	}

	if this.dnsServiceIP != "" {
		this.DNSServiceIP = net.ParseIP(this.dnsServiceIP)
		if this.DNSServiceIP == nil {
			return fmt.Errorf("invalid ip of coredns service: %s", this.coreDNSServiceIP)
		}
	}
	if this.DNSServiceIP == nil {
		if this.ServiceCIDR != nil {
			this.DNSServiceIP = tcp.SubIP(this.ServiceCIDR, CLUSTER_DNS_IP)
		}
	}

	switch this.Mode {
	case RUN_MODE_NONE:
	case RUN_MODE_BRIDGE:
	case RUN_MODE_WIREGUARD:
	default:
		return fmt.Errorf("invalid run mode %q: select %s, %s or %s",
			this.Mode, RUN_MODE_BRIDGE, RUN_MODE_WIREGUARD, RUN_MODE_NONE)
	}
	this.DNSPropagation = strings.ToLower(this.DNSPropagation)
	switch this.DNSPropagation {
	case DNSMODE_KUBERNETES, DNSMODE_DNS, DNSMODE_NONE:
	default:
		return fmt.Errorf("invalid dns mode: %s", this.DNSPropagation)
	}
	return nil
}

func (this *Config) MatchLink(obj *v1alpha1.KubeLink) (bool, net.IP) {
	ip, cidr, err := net.ParseCIDR(obj.Spec.ClusterAddress)
	if err != nil {
		return false, nil
	}
	if !this.Responsible.Contains("all") && !this.Responsible.Contains(cidr.String()) {
		return false, nil
	}
	return this.ClusterCIDR.Contains(ip), ip
}
