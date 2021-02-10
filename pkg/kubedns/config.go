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

package kubedns

import (
	"fmt"
	"net"

	"github.com/gardener/controller-manager-library/pkg/config"

	"github.com/mandelsoft/kubelink/pkg/tcp"
	"github.com/mandelsoft/kubelink/pkg/utils"
)

type Config struct {
	// shared
	serviceCIDR string
	ServiceCIDR *net.IPNet

	ClusterName   string
	dnsServiceIP  string
	DNSServiceIP  net.IP
	ClusterDomain string

	DNSPropagation    string
	coreDNSServiceIP  string
	CoreDNSServiceIP  net.IP
	CoreDNSDeployment string
	CoreDNSSecret     string
	CoreDNSConfigure  bool
}

func (this *Config) AddOptionsToSet(set config.OptionSet) {
	//this.Config.AddOptionsToSet(set)
	set.AddStringOption(&this.serviceCIDR, "service-cidr", "", "", "CIDR of local service network")

	set.AddStringOption(&this.ClusterName, "cluster-name", "", "", "Name of local cluster in cluster mesh")
	set.AddStringOption(&this.dnsServiceIP, "dns-service-ip", "", "", "IP of Cluster DNS Service (for DNS Propagation)")
	set.AddStringOption(&this.ClusterDomain, "cluster-domain", "", "cluster.local", "Cluster Domain of Cluster DNS Service (for DNS Propagation)")

	set.AddStringOption(&this.DNSPropagation, "dns-propagation", "", "none", "Mode for accessing foreign DNS information (none, dns or kubernetes)")
	set.AddStringOption(&this.coreDNSServiceIP, "coredns-service-ip", "", "", "Service IP of coredns deployment used by kubelink")
	set.AddStringOption(&this.CoreDNSDeployment, "coredns-deployment", "", "kubelink-coredns", "Name of coredns deployment used by kubelink")
	set.AddStringOption(&this.CoreDNSSecret, "coredns-secret", "", "kubelink-coredns", "Name of dns secret used by kubelink")
	set.AddBoolOption(&this.CoreDNSConfigure, "coredns-configure", "", false, "Enable automatic configuration of cluster DNS (coredns)")
}

func (this *Config) Prepare() error {
	var err error

	_, this.ServiceCIDR, err = utils.OptionalCIDR(this.serviceCIDR, "service-cidr")
	if err != nil {
		return err
	}

	if this.coreDNSServiceIP != "" {
		this.CoreDNSServiceIP = net.ParseIP(this.coreDNSServiceIP)
		if this.CoreDNSServiceIP == nil {
			return fmt.Errorf("invalid ip of coredns service: %s", this.coreDNSServiceIP)
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
	return nil
}
