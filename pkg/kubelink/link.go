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
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/iptables"
	"github.com/mandelsoft/kubelink/pkg/tcp"
	"github.com/mandelsoft/kubelink/pkg/utils"
)

const EP_INBOUND = "Inbound"
const EP_LOCAL = "LocalLink"
const EP_NONE = "None"

const DEFAULT_MESH = "<default>"

const LINKNAME_SEP = "--"

////////////////////////////////////////////////////////////////////////////////

type LinkName struct {
	name string
	mesh string
}

func NewLinkName(mesh, name string) LinkName {
	if mesh == "" {
		mesh = DEFAULT_MESH
	}
	return LinkName{
		name: name,
		mesh: mesh,
	}
}

func DecodeLinkNameFromString(name string) LinkName {
	index := strings.Index(name, LINKNAME_SEP)
	if index > 0 {
		return NewLinkName(name[:index], name[index+2:])
	}
	return NewLinkName(DEFAULT_MESH, name)
}

func (this LinkName) Name() string {
	return this.name
}

func (this LinkName) Mesh() string {
	return this.mesh
}

func (this LinkName) String() string {
	return this.mesh + LINKNAME_SEP + this.name
}

////////////////////////////////////////////////////////////////////////////////

type LinkSpec = api.KubeLinkSpec

func LinkForSpec(name LinkName, spec *LinkSpec, defaultPort int, gw net.IP) (*Link, error) {
	var egress tcp.CIDRList
	var serviceCIDR *net.IPNet
	var gateway *LinkName
	if spec.Endpoint == EP_LOCAL {
		if spec.GatewayLink != "" {
			return nil, fmt.Errorf("local links must not use a gateway")
		}
		if len(spec.Egress) != 0 {
			return nil, fmt.Errorf("no egress possible for local links")
		}
		if len(spec.Ingress) != 0 {
			return nil, fmt.Errorf("no ingress possible for local links")
		}
	}
	if spec.GatewayLink != "" {
		gw := DecodeLinkNameFromString(spec.GatewayLink)
		if gw == name {
			return nil, fmt.Errorf("no self link for gateway link")
		}
		gateway = &gw
	}

	if !utils.Empty(spec.CIDR) {
		_, cidr, err := net.ParseCIDR(spec.CIDR)
		if err != nil {
			return nil, fmt.Errorf("invalid service cidr %q: %s", spec.CIDR, err)
		}
		serviceCIDR = cidr
		if spec.Endpoint != EP_LOCAL {
			egress.Add(cidr)
		}
	}
	for _, c := range spec.Egress {
		cidr, err := tcp.ParseNet(c)
		if err != nil {
			return nil, fmt.Errorf("invalid routing cidr %q: %s", spec.CIDR, err)
		}
		egress.Add(cidr)
	}

	ingress, err := ParseFirewallRule(spec.Ingress)
	if err != nil {
		return nil, fmt.Errorf("invalid cluster ingress: %s", err)
	}

	if spec.ClusterAddress == "" {
		return nil, fmt.Errorf("cluster address missing")
	}
	ip, ccidr, err := net.ParseCIDR(spec.ClusterAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid cluster address %q: %s", spec.ClusterAddress, err)
	}
	ccidr.IP = ip
	if spec.Endpoint == "" && spec.GatewayLink == "" {
		return nil, fmt.Errorf("endpoint or gateway link missing")
	}

	endpoint := spec.Endpoint
	host := ""
	port := defaultPort
	if endpoint != EP_LOCAL && endpoint != EP_INBOUND {
		if len(endpoint) == 0 {
			return nil, fmt.Errorf("endpoint required")
		}
		parts := strings.Split(endpoint, ":")
		if len(parts) == 1 {
			endpoint = fmt.Sprintf("%s:%d", endpoint, port)
		} else {
			i, err := strconv.ParseInt(parts[1], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid gateway port %q: %s", parts[1], err)
			}
			port = int(i)
		}
		host = parts[0]
	}

	var publicKey *wgtypes.Key
	if !utils.Empty(spec.PublicKey) {
		key, err := wgtypes.ParseKey(spec.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid public wireguard key %q: %s", spec.PublicKey, err)
		}
		publicKey = &key
	}
	var presharedKey *wgtypes.Key
	if !utils.Empty(spec.PresharedKey) {
		key, err := wgtypes.ParseKey(spec.PresharedKey)
		if err != nil {
			return nil, fmt.Errorf("invalid preshared wireguard key: %s", err)
		}
		presharedKey = &key
	}

	dnsInfo := LinkDNSInfo{}
	if spec.DNS != nil {
		if spec.DNS.OmitDNSPropagation == nil || *spec.DNS.OmitDNSPropagation {
			dnsInfo.DNSPropagation = true
			dnsInfo.ClusterDomain = spec.DNS.BaseDomain
			if dnsInfo.ClusterDomain == "" {
				if spec.Endpoint == EP_LOCAL {
					return nil, fmt.Errorf("dns propgation requires dns base domain for local links")
				}
				dnsInfo.ClusterDomain = "cluster.local"
			}
			if spec.Endpoint == EP_LOCAL {
				if dnsInfo.DnsIP != nil {
					return nil, fmt.Errorf("no dns ip for local link")
				}
			} else {
				if dnsInfo.DnsIP == nil {
					if serviceCIDR != nil {
						dnsInfo.DnsIP = tcp.SubIP(serviceCIDR, CLUSTER_DNS_IP)
					} else {
						return nil, fmt.Errorf("dns service ip required for dns propagation")
					}
				}
			}
		}
	}
	link := &Link{
		Name:            name,
		ServiceCIDR:     serviceCIDR,
		Egress:          egress,
		Ingress:         ingress,
		ClusterAddress:  ccidr,
		GatewayLink:     gateway,
		Host:            host,
		Port:            port,
		Endpoint:        endpoint,
		PublicKey:       publicKey,
		PresharedKey:    presharedKey,
		Gateway:         gw,
		LinkForeignData: LinkForeignData{LinkDNSInfo: dnsInfo},
	}
	return link, nil
}

////////////////////////////////////////////////////////////////////////////////

type LinkNameSet map[LinkName]struct{}

func NewLinkNameSet(names ...LinkName) LinkNameSet {
	r := LinkNameSet{}
	r.Add(names...)
	return r
}

func (this LinkNameSet) Contains(n LinkName) bool {
	_, ok := this[n]
	return ok
}

func (this LinkNameSet) Add(names ...LinkName) {
	for _, n := range names {
		this[n] = struct{}{}
	}
}

func (this LinkNameSet) Remove(n LinkName) {
	delete(this, n)
}

func (this LinkNameSet) AddAll(sets ...LinkNameSet) LinkNameSet {
	for _, set := range sets {
		for n := range set {
			this[n] = struct{}{}
		}
	}
	return this
}

func (this LinkNameSet) Copy() LinkNameSet {
	r := LinkNameSet{}
	if this != nil {
		for n := range this {
			r.Add(n)
		}
	}
	return r
}

////////////////////////////////////////////////////////////////////////////////

type Link struct {
	Name           LinkName
	ServiceCIDR    *net.IPNet
	Egress         tcp.CIDRList
	Ingress        *FirewallRule
	ClusterAddress *net.IPNet
	GatewayLink    *LinkName
	GatewayFor     LinkNameSet
	Gateway        net.IP
	Host           string
	Port           int
	Endpoint       string
	PublicKey      *wgtypes.Key
	PresharedKey   *wgtypes.Key
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
	t := "endpoint"
	if this.IsLocalLink() {
		t = "local"
	} else {
		if this.IsInbound() {
			t = "inbound"
		}
	}
	return fmt.Sprintf("%s(%s,%s)[%s,%s,%s,%d,%s]",
		this.Name.name, this.Name.mesh, t, this.ClusterAddress, this.Egress, this.Host, this.Port, this.PublicKey)
}

func (this *Link) IsInbound() bool {
	return this.Endpoint == EP_INBOUND
}

func (this *Link) IsLocalLink() bool {
	return this.Endpoint == EP_LOCAL
}

func (this *Link) HasEndpoint() bool {
	return !this.IsLocalLink() && !this.IsInbound()
}

func (this *Link) MatchMesh(cidr *net.IPNet) bool {
	return tcp.EqualCIDR(tcp.CIDRNet(this.ClusterAddress), cidr)
}

func (this *Link) GetRequired() LinkNameSet {
	if this.GatewayLink == nil {
		return LinkNameSet{}
	}
	return NewLinkNameSet(*this.GatewayLink)
}

func (this *Link) AllowIngress(ip net.IP) (granted bool, set bool) {
	if !this.Ingress.IsSet() {
		return true, false
	}
	if ip.Equal(this.ClusterAddress.IP) {
		return true, true
	}
	return this.Ingress.Contains(ip), true
}

func (this *Link) GetIngressChain() *iptables.ChainRequest {
	if !this.Ingress.IsSet() {
		return nil
	}
	rules := iptables.Rules{
		iptables.Rule{
			iptables.Opt("-m", "comment", "--comment", "firewall settings for link "+this.Name.String()),
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
		FW_LINK_CHAIN_PREFIX+encodeName(this.Name.String()),
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
