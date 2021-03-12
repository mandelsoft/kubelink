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

package kubelink

import (
	"fmt"
	"net"

	utils2 "github.com/gardener/controller-manager-library/pkg/utils"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/mandelsoft/kubelink/pkg/iptables"
	"github.com/mandelsoft/kubelink/pkg/tcp"
	"github.com/mandelsoft/kubelink/pkg/utils"
)

const EP_INBOUND = "Inbound"
const EP_LOCAL = "LocalLink"

////////////////////////////////////////////////////////////////////////////////

type Link struct {
	Name           string
	ServiceCIDR    *net.IPNet
	Egress         tcp.CIDRList
	Ingress        *FirewallRule
	ClusterAddress *net.IPNet
	GatewayLink    string
	GatewayFor     utils2.StringSet
	Gateway        net.IP
	Host           string
	Port           int
	Endpoint       string
	PublicKey      *wgtypes.Key
	LinkForeignData
}

type LinkAccessInfo struct {
	CACert string
	Token  string
}

func (this LinkAccessInfo) String() string {
	return fmt.Sprintf("{ca:%s..., token:%s...}", utils.ShortenString(this.CACert, 35), utils.ShortenString(this.Token, 35))
}

func (this LinkAccessInfo) Equal(other LinkAccessInfo) bool {
	return this.CACert == other.CACert && this.Token == other.Token
}

type LinkDNSInfo struct {
	ClusterDomain  string
	DnsIP          net.IP
	DNSPropagation bool
}

func (this LinkDNSInfo) String() string {
	return fmt.Sprintf("{cluster-domain:%s, dns-ip:%s, propagation:%t}", this.ClusterDomain, this.DnsIP, this.DNSPropagation)
}

func (this LinkDNSInfo) Equal(other LinkDNSInfo) bool {
	return this.DnsIP.Equal(other.DnsIP) &&
		this.ClusterDomain == other.ClusterDomain &&
		this.DNSPropagation == other.DNSPropagation
}

type LinkForeignData struct {
	UpdatePending bool
	LinkAccessInfo
	LinkDNSInfo
}

func (this *Link) String() string {
	return fmt.Sprintf("%s[%s,%s,%s]", this.Name, this.ClusterAddress, this.Egress, this.Endpoint)
}

func (this *Link) MatchMesh(cidr *net.IPNet) bool {
	return tcp.EqualCIDR(tcp.CIDRNet(this.ClusterAddress), cidr)
}

func (this *Link) IsInbound() bool {
	return this.Endpoint == EP_INBOUND
}

func (this *Link) IsLocalLink() bool {
	return this.Endpoint == EP_LOCAL
}

func (this *Link) GetRequired() utils2.StringSet {
	if this.GatewayLink == "" {
		return utils2.StringSet{}
	}
	return utils2.NewStringSet(this.GatewayLink)
}

func (this *Link) AllowIngress(ip net.IP) (granted bool, set bool) {
	if !this.Ingress.IsSet() {
		return true, false
	}
	return this.Ingress.Contains(ip), true
}

func (this *Link) GetIngressChain() *iptables.ChainRequest {
	if !this.Ingress.IsSet() {
		return nil
	}
	rules := iptables.Rules{
		iptables.Rule{
			iptables.Opt("-m", "comment", "--comment", "firewall settings for link "+this.Name),
		},
	}
	for _, i := range this.Ingress.Denied {
		rules = append(rules, iptables.Rule{
			iptables.Opt("-d", i.String()),
			iptables.Opt("-j", DROP_ACTION),
		})
	}
	if this.Ingress.Allowed.IsSet() {
		for _, i := range this.Ingress.Allowed {
			rules = append(rules, iptables.Rule{
				iptables.Opt("-d", i.String()),
				iptables.Opt("-j", "RETURN"),
			})
		}
		rules = append(rules, iptables.Rule{
			iptables.Opt("-j", DROP_ACTION),
		})
	}
	return iptables.NewChainRequest(
		TABLE_LINK_CHAIN,
		FW_LINK_CHAIN_PREFIX+encodeName(this.Name),
		rules, true)
}

func (this *Link) IsWireguard() bool {
	return this.PublicKey != nil && this.Endpoint != "none"
}

func (this *Link) AcceptIP(ip net.IP) bool {
	if this.ClusterAddress.IP.Equal(ip) {
		return true
	}
	if this.Egress.Contains(ip) {
		return true
	}
	return false
}
