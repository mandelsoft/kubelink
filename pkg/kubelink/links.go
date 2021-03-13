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
	utils2 "github.com/gardener/controller-manager-library/pkg/utils"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/apimachinery/pkg/labels"

	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	//"github.com/mandelsoft/kubelink/pkg/controllers/broker/config"
	"github.com/mandelsoft/kubelink/pkg/tcp"
	"github.com/mandelsoft/kubelink/pkg/utils"
)

const DEFAULT_PORT = 80

const DNSMODE_NONE = "none"
const DNSMODE_KUBERNETES = "kubernetes"
const DNSMODE_DNS = "dns"

type MeshInfo struct {
	Name           string
	ClusterName    string
	ClusterAddress *net.IPNet
	CIDR           *net.IPNet
	DNSInfo        LinkDNSInfo
}

func (this *MeshInfo) PropagateDNS() bool {
	return this.DNSInfo.DNSPropagation && this.ClusterName != ""
}

////////////////////////////////////////////////////////////////////////////////

func (this *Links) linkFor(link *api.KubeLink) (*Link, utils2.StringSet, error) {
	var egress tcp.CIDRList
	var serviceCIDR *net.IPNet

	required := utils2.StringSet{}
	if link.Spec.Endpoint == EP_LOCAL {
		if link.Spec.GatewayLink != "" {
			return nil, required, fmt.Errorf("local links must not use a gateway")
		}
		if len(link.Spec.Egress) != 0 {
			return nil, required, fmt.Errorf("no egress possible for local links")
		}
		if len(link.Spec.Ingress) != 0 {
			return nil, required, fmt.Errorf("no ingress possible for local links")
		}
	}
	if link.Spec.GatewayLink != "" {
		required.Add(link.Spec.GatewayLink)
	}
	if !utils.Empty(link.Spec.CIDR) {
		_, cidr, err := net.ParseCIDR(link.Spec.CIDR)
		if err != nil {
			return nil, required, fmt.Errorf("invalid routing cidr %q: %s", link.Spec.CIDR, err)
		}
		serviceCIDR = cidr
		egress.Add(cidr)
	}
	for _, c := range link.Spec.Egress {
		cidr, err := tcp.ParseNet(c)
		if err != nil {
			return nil, required, fmt.Errorf("invalid routing cidr %q: %s", link.Spec.CIDR, err)
		}
		egress.Add(cidr)
	}

	ingress, err := ParseFirewallRule(link.Spec.Ingress)
	if err != nil {
		return nil, required, fmt.Errorf("invalid cluster ingress: %s", err)
	}

	ip, ccidr, err := net.ParseCIDR(link.Spec.ClusterAddress)
	if err != nil {
		return nil, required, fmt.Errorf("invalid cluster address %q: %s", link.Spec.ClusterAddress, err)
	}
	ccidr.IP = ip
	if link.Spec.Endpoint == "" && link.Spec.GatewayLink == "" {
		return nil, required, fmt.Errorf("no endpoint or gateway link")
	}
	if link.Spec.GatewayLink != "" {
		if len(this.usersOf[link.Name]) != 0 {
			return nil, required, fmt.Errorf("link is gateway for %s and cannot use gateway", this.usersOf[link.Name])
		}
		if valid, known := this.IsValid(link.Spec.GatewayLink); !known {
			return nil, required, fmt.Errorf("gateway link %q not found", link.Spec.GatewayLink)
		} else {
			if !valid {
				return nil, required, fmt.Errorf("gateway link %q is invalid", link.Spec.GatewayLink)
			}
		}
	}

	var gateway net.IP
	if link.Status.Gateway != "" {
		gateway = net.ParseIP(link.Status.Gateway)
		if gateway == nil {
			return nil, required, fmt.Errorf("invalid gateway address %q", link.Status.Gateway)
		}
	}

	endpoint := link.Spec.Endpoint
	parts := strings.Split(endpoint, ":")
	port := this.defaultport
	if len(endpoint) != 0 && endpoint != EP_INBOUND && endpoint != EP_LOCAL {
		if len(parts) == 1 {
			endpoint = fmt.Sprintf("%s:%d", endpoint, port)
		} else {
			i, err := strconv.ParseInt(parts[1], 10, 32)
			if err != nil {
				return nil, required, fmt.Errorf("invalid gateway port %q: %s", parts[1], err)
			}
			port = int(i)
		}
	}

	var publicKey *wgtypes.Key
	if !utils.Empty(link.Spec.PublicKey) {
		key, err := wgtypes.ParseKey(link.Spec.PublicKey)
		if err != nil {
			return nil, required, fmt.Errorf("invalid public wireguard key %q: %s", link.Spec.PublicKey, err)
		}
		publicKey = &key
	}

	l := &Link{
		Name:           link.Name,
		ServiceCIDR:    serviceCIDR,
		Egress:         egress,
		Ingress:        ingress,
		ClusterAddress: ccidr,
		GatewayLink:    link.Spec.GatewayLink,
		GatewayFor:     utils2.StringSet{},
		Gateway:        gateway,
		Host:           parts[0],
		Port:           port,
		Endpoint:       endpoint,
		PublicKey:      publicKey,
	}
	return l, required, nil
}

////////////////////////////////////////////////////////////////////////////////

var linksKey = ctxutil.SimpleKey("kubelinks")

func GetSharedLinks(controller controller.Interface, defaultport int) *Links {
	return controller.GetEnvironment().GetOrCreateSharedValue(linksKey, func() interface{} {
		resc, err := controller.GetMainCluster().Resources().Get(&api.KubeLink{})
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
	gateway     net.IP

	usersOf      map[string]utils2.StringSet
	known        utils2.StringSet
	meshesByLink map[string]*Link
	meshesByName map[string]*Link
	defaultMesh  *Link
}

func NewLinks(resc resources.Interface, defaultport int) *Links {
	return &Links{
		resource:     resc,
		defaultport:  defaultport,
		links:        map[string]*Link{},
		meshesByLink: map[string]*Link{},
		meshesByName: map[string]*Link{},
		endpoints:    map[string]*Link{},
		clusteraddr:  map[string]*Link{},
		usersOf:      map[string]utils2.StringSet{},
		known:        utils2.StringSet{},
		defaultMesh:  nil,
	}
}

func (this *Links) setupLinks(kind string, list []resources.Object, cond func(*api.KubeLink) bool) {
	for _, l := range list {
		o := l.Data().(*api.KubeLink)
		if cond != nil && cond(o) {
			link, err := this.updateLink(o)
			if link != nil {
				logger.Infof("found %s %s", kind, link)
			}
			if err != nil {
				logger.Infof("erroneous %s %s: %s", kind, l.GetName(), err)
			}
		}
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
	res, _ := cluster.Resources().Get(api.KUBELINK)
	list, _ := res.ListCached(labels.Everything())

	// first setup meshes (LocalLinks)
	this.setupLinks("mesh", list, func(l *api.KubeLink) bool { return l.Spec.Endpoint == EP_LOCAL })
	// the setup foreign links
	this.setupLinks("mesh", list, func(l *api.KubeLink) bool { return l.Spec.Endpoint != EP_LOCAL })
}

func (this *Links) SetDefaultMesh(name string, clusterAddress *net.IPNet, meshDNS LinkDNSInfo) {
	this.lock.Lock()
	defer this.lock.Unlock()
	defaultMesh := &Link{
		Name:           name,
		ClusterAddress: clusterAddress,
		Endpoint:       EP_LOCAL,
	}
	defaultMesh.LinkDNSInfo = meshDNS
	this.defaultMesh = defaultMesh
}

func (this *Links) SetGateway(ip net.IP) {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.gateway = ip
}

func (this *Links) GetGateway() net.IP {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.gateway
}

func (this *Links) IsKnown(name string) bool {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.known.Contains(name)
}

func (this *Links) IsValid(name string) (valid bool, known bool) {
	this.lock.Lock()
	defer this.lock.Unlock()
	known = this.known.Contains(name)
	valid = this.links[name] != nil
	return
}

func (this *Links) GetMeshLinks() map[string]*Link {
	this.lock.Lock()
	defer this.lock.Unlock()
	r := map[string]*Link{}
	for k, v := range this.meshesByLink {
		r[k] = v
	}
	if this.defaultMesh != nil && r[this.defaultMesh.Name] == nil {
		r[this.defaultMesh.Name] = this.defaultMesh
	}
	return r
}

func ExtractNames(s string) (mesh, cluster string) {
	i := strings.Index(s, "--")
	mesh = s
	cluster = s
	if i > 0 {
		mesh = s[:i]
		cluster = s[i+1:]
	}
	return
}

func (this *Links) GetMeshInfos() map[string]*MeshInfo {
	this.lock.Lock()
	defer this.lock.Unlock()
	r := map[string]*MeshInfo{}
	for _, v := range this.meshesByLink {
		mesh, name := ExtractNames(v.Name)
		r[mesh] = &MeshInfo{
			Name:           mesh,
			ClusterName:    name,
			ClusterAddress: v.ClusterAddress,
			CIDR:           tcp.CIDRNet(v.ClusterAddress),
			DNSInfo:        v.LinkDNSInfo,
		}
	}
	if this.defaultMesh != nil {
		mesh, cluster := ExtractNames(this.defaultMesh.Name)
		if r[mesh] == nil {
			r[mesh] = &MeshInfo{
				Name:           mesh,
				ClusterName:    cluster,
				ClusterAddress: this.defaultMesh.ClusterAddress,
				CIDR:           tcp.CIDRNet(this.defaultMesh.ClusterAddress),
				DNSInfo:        this.defaultMesh.LinkDNSInfo,
			}
		}
	}
	return r
}

func (this *Links) addGatewayFor(gw, name string) {
	if cur := this.links[gw]; cur != nil {
		cur.GatewayFor.Add(name)
	}
}
func (this *Links) removeGatewayFor(gw, name string) {
	if cur := this.links[gw]; cur != nil {
		cur.GatewayFor.Remove(name)
	}
}

func (this *Links) updateUsesOf(name string, wait utils2.StringSet) {
	for req, w := range this.usersOf {
		if wait.Contains(req) {
			w.Add(name)
			wait.Remove(req)
			this.addGatewayFor(req, name)
		} else {
			w.Remove(name)
			this.removeGatewayFor(req, name)
		}
	}
	for req := range wait {
		this.usersOf[req] = utils2.NewStringSet(name)
		this.addGatewayFor(req, name)
	}
}

func (this *Links) removeUser(name string) {
	for _, w := range this.usersOf {
		delete(w, name)
	}
}

func (this *Links) GetUsersOf(name string) utils2.StringSet {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.usersOf[name].Copy()
}

func (this *Links) LinkInfoUpdated(logger logger.LogContext, name string, access *LinkAccessInfo, dns *LinkDNSInfo) *Link {
	this.lock.Lock()
	defer this.lock.Unlock()
	old := this.links[name]
	this.removeUser(name)
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
	if old == nil {
		old = this.meshesByLink[name]
	}
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

func (this *Links) ReplaceLink(link *Link) *Link {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.replaceLink(link)
}

func (this *Links) replaceLink(link *Link) *Link {
	cur := this.links[link.Name]

	if link.IsLocalLink() {
		if cur != nil {
			delete(this.links, link.Name)
			delete(this.endpoints, link.Name)
			delete(this.clusteraddr, link.Name)
		}
		this.meshesByLink[link.Name] = link
	} else {
		delete(this.meshesByLink, link.Name)
		if cur != nil {
			link.GatewayFor = cur.GatewayFor
		}

		this.links[link.Name] = link
		this.endpoints[link.Host] = link
		this.clusteraddr[link.ClusterAddress.IP.String()] = link
	}
	return link
}

func (this *Links) UpdateLink(klink *api.KubeLink) (*Link, error) {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.updateLink(klink)
}

func (this *Links) GetLink(name string) *Link {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.links[name]
}

func (this *Links) GetMeshLink(name string) *Link {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.meshesByLink[name]
}

func (this *Links) updateLink(klink *api.KubeLink) (*Link, error) {
	name := klink.Name
	l, wait, err := this.linkFor(klink)
	this.updateUsesOf(name, wait)
	this.known.Add(name)
	if err != nil {
		return nil, err
	}
	old := this.links[name]
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
	cur := this.links[name]
	if cur != nil {
		delete(this.links, name)
		delete(this.endpoints, cur.Host)
		delete(this.clusteraddr, cur.ClusterAddress.IP.String())

		for _, l := range this.links {
			this.updateUsesOf(name, l.GetRequired())
		}
	}
	delete(this.known, name)
	delete(this.meshesByLink, name)
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

func (this *Links) IsGateway(ifce *NodeInterface) bool {
	if ifce == nil {
		return false
	}
	this.lock.RLock()
	defer this.lock.RUnlock()
	if this.gateway != nil && this.gateway.Equal(ifce.IP) {
		return true
	}
	for _, l := range this.links {
		if l.Gateway != nil && l.Gateway.Equal(ifce.IP) {
			return true
		}
	}
	return false
}

func (this *Links) LookupMeshGatewaysFor(ip net.IP) (*net.IPNet, []net.IP) {
	this.lock.RLock()
	defer this.lock.RUnlock()

	var gateways []net.IP
	var cidr *net.IPNet

	if this.gateway != nil {
		gateways = append(gateways, this.gateway)
	}
	for _, l := range this.links {
		if l.ClusterAddress.Contains(ip) {
			cidr = tcp.CIDRNet(l.ClusterAddress)
			if l.Gateway != nil {
				if !tcp.IPList(gateways).Contains(l.Gateway) {
					gateways = append(gateways, l.Gateway)
				}
			}
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
		if l.AcceptIP(ip) && l.GatewayLink == "" {
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

func (this *Links) GetLocalAddressForClusterAddress(ip net.IP) *net.IPNet {
	m := this.GetMeshForClusterAddress(ip)
	if m == nil {
		return nil
	}
	return m.ClusterAddress
}

func (this *Links) GetMeshForClusterAddress(ip net.IP) *Link {
	this.lock.RLock()
	defer this.lock.RUnlock()
	l := this.clusteraddr[ip.String()]
	if l == nil {
		return nil
	}
	for _, m := range this.meshesByLink {
		if m.ClusterAddress.Contains(ip) {
			return m
		}
	}
	return nil
}

func (this *Links) GetLinkForEndpoint(dnsname string) *Link {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.endpoints[dnsname]
}

func (this *Links) getGatewayFor(l *Link) net.IP {
	gateway := this.gateway
	if gateway == nil {
		gateway = l.Gateway
	}
	return gateway
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
			logger.Infof("*** found active tunl0[%d]\n", index)
			flags = netlink.FLAG_ONLINK
		}
	}
	routes := Routes{}
	for _, l := range this.links {
		gateway := this.getGatewayFor(l)
		if gateway == nil || !gateway.Equal(ifce.IP) {
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
	routes := Routes{}
	for _, c := range this.GetGatewayEgress(ifce, nil) {
		r := netlink.Route{
			Dst:       c,
			LinkIndex: link.Attrs().Index,
		}
		routes.Add(r)
	}
	return routes
}

func (this *Links) matchGateway(l *Link, ifce *NodeInterface) bool {
	if ifce == nil {
		return true
	}
	gateway := this.getGatewayFor(l)
	return gateway != nil && gateway.Equal(ifce.IP)
}

func (this *Links) matchMesh(l *Link, mesh *net.IPNet) bool {
	return mesh == nil || mesh.Contains(l.ClusterAddress.IP)
}

func (this *Links) GetGatewayEgress(ifce *NodeInterface, mesh *net.IPNet) tcp.CIDRList {
	this.lock.RLock()
	defer this.lock.RUnlock()

	egress := tcp.CIDRList{}
	for _, l := range this.links {
		if this.matchGateway(l, ifce) && this.matchMesh(l, mesh) {
			for _, c := range l.Egress {
				egress = append(egress, c)
			}
		}
	}
	for _, m := range this.meshesByLink {
		if this.matchMesh(m, mesh) {
			egress = append(egress, tcp.CIDRNet(m.ClusterAddress))
		}
	}
	return egress
}

func (this *Links) RegisterLink(name string, clusterCIDR *net.IPNet, fqdn string, cidr *net.IPNet) (*Link, error) {
	kl := &api.KubeLink{}
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
