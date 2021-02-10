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

package kubelink

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/cluster"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/ctxutil"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/iptables"
	"github.com/mandelsoft/kubelink/pkg/tcp"
	"github.com/mandelsoft/kubelink/pkg/utils"
)

const DEFAULT_PORT = 80

////////////////////////////////////////////////////////////////////////////////

type Link struct {
	Name           string
	ServiceCIDR    *net.IPNet
	Egress         tcp.CIDRList
	Ingress        tcp.CIDRList
	ClusterAddress *net.IPNet
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
	ClusterDomain string
	DnsIP         net.IP
}

func (this LinkDNSInfo) String() string {
	return fmt.Sprintf("{cluster-domain:%s, dns-ip:%s}", this.ClusterDomain, this.DnsIP)
}

func (this LinkDNSInfo) Equal(other LinkDNSInfo) bool {
	return this.DnsIP.Equal(other.DnsIP) && this.ClusterDomain == other.ClusterDomain
}

type LinkForeignData struct {
	UpdatePending bool
	LinkAccessInfo
	LinkDNSInfo
}

func (this *Link) String() string {
	return fmt.Sprintf("%s[%s,%s,%s]", this.Name, this.ClusterAddress, this.Egress, this.Endpoint)
}

func (this *Link) AllowIngress(ip net.IP) (granted bool, set bool) {
	if !this.Ingress.IsSet() {
		return true, false
	}
	return this.Ingress.Contains(ip), true
}

func (this *Link) IsWireguard() bool {
	return this.PublicKey != nil && this.Endpoint != "none"
}

////////////////////////////////////////////////////////////////////////////////

func (this *Links) LinkFor(link *v1alpha1.KubeLink) (*Link, error) {
	var egress tcp.CIDRList
	var serviceCIDR *net.IPNet

	if !utils.Empty(link.Spec.CIDR) {
		_, cidr, err := net.ParseCIDR(link.Spec.CIDR)
		if err != nil {
			return nil, fmt.Errorf("invalid routing cidr %q: %s", link.Spec.CIDR, err)
		}
		serviceCIDR = cidr
		egress.Add(cidr)
	}
	for _, c := range link.Spec.Egress {
		_, cidr, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("invalid routing cidr %q: %s", link.Spec.CIDR, err)
		}
		egress.Add(cidr)
	}
	var ingress tcp.CIDRList

	for _, c := range link.Spec.Ingress {
		_, cidr, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("invalid routing cidr %q: %s", link.Spec.CIDR, err)
		}
		ingress.Add(cidr)
	}

	ip, ccidr, err := net.ParseCIDR(link.Spec.ClusterAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid cluster address %q: %s", link.Spec.ClusterAddress, err)
	}
	ccidr.IP = ip
	if link.Spec.Endpoint == "" {
		return nil, fmt.Errorf("no endpoint")
	}
	if link.Status.Gateway == "" {
		return nil, fmt.Errorf("no gateway address")
	}
	gateway := net.ParseIP(link.Status.Gateway)
	if gateway == nil {
		return nil, fmt.Errorf("invalid gateway address %q", link.Status.Gateway)
	}

	endpoint := link.Spec.Endpoint
	parts := strings.Split(endpoint, ":")
	port := this.defaultport
	if len(endpoint) != 0 && endpoint != "none" {
		if len(parts) == 1 {
			endpoint = fmt.Sprintf("%s:%d", endpoint, port)
		} else {
			i, err := strconv.ParseInt(parts[1], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid gateway port %q: %s", parts[1], err)
			}
			port = int(i)
		}
	}

	var publicKey *wgtypes.Key
	if !utils.Empty(link.Spec.PublicKey) {
		key, err := wgtypes.ParseKey(link.Spec.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid public wireguard key %q: %s", link.Spec.PublicKey, err)
		}
		publicKey = &key
	}

	l := &Link{
		Name:           link.Name,
		ServiceCIDR:    serviceCIDR,
		Egress:         egress,
		Ingress:        ingress,
		ClusterAddress: ccidr,
		Gateway:        gateway,
		Host:           parts[0],
		Port:           port,
		Endpoint:       endpoint,
		PublicKey:      publicKey,
	}
	return l, err
}

////////////////////////////////////////////////////////////////////////////////

var linksKey = ctxutil.SimpleKey("kubelinks")

func GetSharedLinks(controller controller.Interface, defaultport int) *Links {
	return controller.GetEnvironment().GetOrCreateSharedValue(linksKey, func() interface{} {
		resc, err := controller.GetMainCluster().Resources().Get(&v1alpha1.KubeLink{})
		if err != nil {
			controller.Errorf("cannot get kubelink resource: %s", err)
		}
		return NewLinks(resc, defaultport)
	}).(*Links)
}

type Links struct {
	lock        sync.RWMutex
	resource    resources.Interface
	initialized bool
	defaultport int
	links       map[string]*Link
	endpoints   map[string]*Link
	clusteraddr map[string]*Link
}

func NewLinks(resc resources.Interface, defaultport int) *Links {
	return &Links{
		resource:    resc,
		defaultport: defaultport,
		links:       map[string]*Link{},
		endpoints:   map[string]*Link{},
		clusteraddr: map[string]*Link{},
	}
}

func (this *Links) Setup(logger logger.LogContext, cluster cluster.Interface) {
	this.lock.Lock()
	defer this.lock.Unlock()

	if this.initialized {
		return
	}
	this.initialized = true
	if logger != nil {
		logger.Infof("setup links")
	}
	res, _ := cluster.Resources().Get(v1alpha1.KUBELINK)
	list, _ := res.ListCached(labels.Everything())

	for _, l := range list {
		link, err := this.updateLink(l.Data().(*v1alpha1.KubeLink))
		if link != nil {
			logger.Infof("found link %s", link)
		}
		if err != nil {
			logger.Infof("errorneous link %s: %s", l.GetName(), err)
		}
	}
}

func (this *Links) LinkInfoUpdated(logger logger.LogContext, name string, access *LinkAccessInfo, dns *LinkDNSInfo) *Link {
	this.lock.Lock()
	defer this.lock.Unlock()
	old := this.links[name]
	if old != nil {
		new := *old
		if access != nil && old.LinkAccessInfo.Equal(*access) {
			new.UpdatePending = false
			logger.Infof("access updated for link %s: %s", name, access)
		} else {
			access = nil
		}
		if dns != nil && old.LinkDNSInfo.Equal(*dns) {
			new.UpdatePending = false
			logger.Infof("dns info updated for link %s: %s", name, dns)
		} else {
			dns = nil
		}
		if access != nil || dns != nil {
			return this.replaceLink(&new)
		}
	}
	return old
}

func (this *Links) UpdateLinkInfo(logger logger.LogContext, name string, access *LinkAccessInfo, dns *LinkDNSInfo, pending bool) (*Link, bool) {
	this.lock.Lock()
	defer this.lock.Unlock()
	old := this.links[name]
	if old != nil {
		new := *old
		if access != nil && !old.LinkAccessInfo.Equal(*access) {
			if !old.UpdatePending || pending {
				new.LinkAccessInfo = *access
				new.UpdatePending = pending
				if pending {
					logger.Infof("new access info pending for link %s", name)
				} else {
					logger.Infof("updated access info for link %s", name)
				}
			} else {
				access = nil
			}
		} else {
			access = nil
		}
		if dns != nil && !old.LinkDNSInfo.Equal(*dns) {
			if !old.UpdatePending || pending {
				new.LinkDNSInfo = *dns
				new.UpdatePending = pending
				if pending {
					logger.Infof("new dns info pending for link %s", name)
				} else {
					logger.Infof("updated dns info for link %s", name)
				}
			} else {
				dns = nil
			}
		} else {
			dns = nil
		}
		if access != nil || dns != nil {
			return this.replaceLink(&new), true
		}
	}
	return old, false
}

func (this *Links) replaceLink(link *Link) *Link {
	this.links[link.Name] = link
	this.endpoints[link.Host] = link
	this.clusteraddr[link.ClusterAddress.IP.String()] = link
	return link
}

func (this *Links) UpdateLink(klink *v1alpha1.KubeLink) (*Link, error) {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.updateLink(klink)
}

func (this *Links) GetLink(name string) *Link {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.links[name]
}

func (this *Links) updateLink(klink *v1alpha1.KubeLink) (*Link, error) {
	l, err := this.LinkFor(klink)
	if err != nil {
		return nil, err
	}
	old := this.links[klink.Name]
	if old != nil {
		if old.Host != l.Host {
			delete(this.endpoints, old.Host)
		}
		if !old.ClusterAddress.IP.Equal(l.ClusterAddress.IP) {
			delete(this.clusteraddr, old.ClusterAddress.IP.String())
		}
		l.LinkForeignData = old.LinkForeignData
	}
	return this.replaceLink(l), nil
}

func (this *Links) RemoveLink(name string) {
	this.lock.Lock()
	defer this.lock.Unlock()
	l := this.links[name]
	if l != nil {
		delete(this.links, name)
		delete(this.endpoints, l.Host)
		delete(this.clusteraddr, l.ClusterAddress.IP.String())
	}
}

func (this *Links) HasWireguard() bool {
	this.lock.Lock()
	defer this.lock.Unlock()
	for _, l := range this.links {
		if l.IsWireguard() {
			return true
		}
	}
	return false
}

func (this *Links) Visit(visitor func(l *Link) bool) {
	this.lock.Lock()
	links := make([]*Link, len(this.links))
	i := 0
	for _, l := range this.links {
		links[i] = l
		i++
	}
	this.lock.Unlock()
	for _, l := range links {
		if !visitor(l) {
			break
		}
	}
}

////////////////////////////////////////////////////////////////////////////////

func (this *Links) GetMeshGatewaysFor(ip net.IP) (*net.IPNet, []net.IP) {
	this.lock.RLock()
	defer this.lock.RUnlock()

	var gateways []net.IP
	var cidr *net.IPNet

	for _, l := range this.links {
		if l.ClusterAddress.Contains(ip) {
			cidr = tcp.CIDRNet(l.ClusterAddress)
			gateways = append(gateways, l.Gateway)
		}
	}
	return cidr, gateways
}

func (this *Links) GetLinkForIP(ip net.IP) *Link {
	this.lock.RLock()
	defer this.lock.RUnlock()

	if l := this.clusteraddr[ip.String()]; l != nil {
		return l
	}
	for _, l := range this.links {
		if l.Egress.Contains(ip) {
			return l
		}
	}
	return nil
}

func (this *Links) GetLinkForClusterAddress(ip net.IP) *Link {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.clusteraddr[ip.String()]
}

func (this *Links) GetLinkForEndpoint(dnsname string) *Link {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.endpoints[dnsname]
}

func (this *Links) GetSNATRules(ifce *NodeInterface) iptables.Requests {
	this.lock.RLock()
	defer this.lock.RUnlock()

	rules := iptables.Rules{}
	for _, l := range this.links {
		if !l.Gateway.Equal(ifce.IP) {
			for _, c := range l.Egress {
				r := iptables.Rule{
					iptables.Opt("-d", c.String()),
					iptables.Opt("-o", ifce.Name),
					iptables.Opt("-j", "SNAT"),
					iptables.Opt("--to-source", ifce.IP.String()),
				}
				rules.Add(r)
			}
		}
	}
	return iptables.Requests{iptables.NewChainRequest("nat", "kubelink", rules, true)}
}

func (this *Links) GetRoutes(ifce *NodeInterface) Routes {
	this.lock.RLock()
	defer this.lock.RUnlock()

	var flags netlink.NextHopFlag
	index := ifce.Index
	protocol := 0
	i, err := netlink.LinkByName("tunl0")
	if i != nil && err == nil {
		attrs := i.Attrs()
		if attrs.Flags&net.FlagUp != 0 {
			index = attrs.Index
			logger.Infof("*** found active tun10[%d]\n", index)
			flags = netlink.FLAG_ONLINK
		}
	}
	routes := Routes{}
	for _, l := range this.links {
		if !l.Gateway.Equal(ifce.IP) {
			for _, c := range l.Egress {
				r := netlink.Route{
					Dst:       c,
					Gw:        l.Gateway,
					LinkIndex: index,
					Protocol:  protocol,
					Priority:  101,
				}
				r.SetFlag(flags)
				routes.Add(r)
			}
			r := netlink.Route{
				Dst:       tcp.CIDRNet(l.ClusterAddress),
				Gw:        l.Gateway,
				LinkIndex: index,
				Protocol:  protocol,
				Priority:  101,
			}
			r.SetFlag(flags)
			routes.Add(r)
		}
	}
	return routes
}

func (this *Links) GetRoutesToLink(ifce *NodeInterface, link netlink.Link) Routes {
	this.lock.RLock()
	defer this.lock.RUnlock()

	routes := Routes{}
	for _, l := range this.links {
		if l.Gateway.Equal(ifce.IP) {
			for _, c := range l.Egress {
				r := netlink.Route{
					Dst:       c,
					LinkIndex: link.Attrs().Index,
				}
				routes.Add(r)
			}
		}
	}
	return routes
}

func (this *Links) RegisterLink(name string, clusterCIDR *net.IPNet, fqdn string, cidr *net.IPNet) (*Link, error) {
	kl := &v1alpha1.KubeLink{}
	kl.Name = name
	kl.Spec.ClusterAddress = clusterCIDR.IP.String()
	kl.Spec.Endpoint = fqdn
	kl.Spec.CIDR = cidr.String()
	_, err := this.resource.Create(kl)
	if err != nil {
		return nil, err
	}
	return this.UpdateLink(kl)
}
