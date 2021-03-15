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
	"sync"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/ctxutil"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/vishvananda/netlink"

	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	//"github.com/mandelsoft/kubelink/pkg/controllers/broker/config"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

const DEFAULT_PORT = 80

const CLUSTER_DNS_IP = 10
const KUBELINK_DNS_IP = 11

const DNSMODE_NONE = "none"
const DNSMODE_KUBERNETES = "kubernetes"
const DNSMODE_DNS = "dns"

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
	serviceCIDR *net.IPNet
	gateway     net.IP

	links  *LinkIndex
	stale  *LinkIndex
	meshes *MeshIndex
}

func NewLinks(resc resources.Interface, defaultport int) *Links {
	return &Links{
		resource:    resc,
		defaultport: defaultport,
		links:       NewLinkIndex(),
		stale:       NewLinkIndex(),
		meshes:      NewMeshIndex(),
	}
}

func (this *Links) setupLinks(logger logger.LogContext, kind string, list []resources.Object, cond func(*api.KubeLink) bool) {
	last := 0

	logger.Infof("setup %s links", kind)
	for len(list) > 0 && len(list) != last {
		logger.Infof("  checking %d entries", len(list))
		stale := []resources.Object{}
		last = len(list)
		for _, l := range list {
			o := l.Data().(*api.KubeLink)
			if cond != nil && cond(o) {
				link, valid, err := this.updateLink(o)
				if err != nil {
					if valid {
						stale = append(stale, l)
					} else {
						logger.Infof("  erroneous %s %s: %s", kind, l.GetName(), err)
					}
				} else {
					if link != nil {
						logger.Infof("  found %s %s", kind, link)
					}
				}
			}
		}
		list = stale
	}
	for _, l := range list {
		logger.Infof("  stale %s %s", kind, l.ObjectName())
	}
}

func (this *Links) Setup(logger logger.LogContext, list []resources.Object) {
	this.lock.Lock()
	defer this.lock.Unlock()

	if this.initialized {
		return
	}
	this.initialized = true
	// first setup meshes (LocalLinks)
	this.setupLinks(logger, "mesh", list, func(l *api.KubeLink) bool { return l.Spec.Endpoint == EP_LOCAL })
	// the setup foreign links
	this.setupLinks(logger, "node", list, func(l *api.KubeLink) bool { return l.Spec.Endpoint != EP_LOCAL })
}

func (this *Links) SetDefaultMesh(clusterName string, clusterAddress *net.IPNet, meshDNS LinkDNSInfo) {
	defaultMesh := &Link{
		Name:           NewLinkName(DEFAULT_MESH, clusterName),
		ClusterAddress: clusterAddress,
		Endpoint:       EP_LOCAL,
	}
	defaultMesh.LinkDNSInfo = meshDNS
	this.meshes.SetDefaultMesh(defaultMesh)
}

func (this *Links) SetGateway(ip net.IP) {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.gateway = ip
}

func (this *Links) GetGateway() net.IP {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.gateway
}

func (this *Links) GetMeshLinks() map[LinkName]*Link {
	return this.meshes.GetMeshLinks()
}

func (this *Links) GetMeshInfos() map[string]*Mesh {
	return this.meshes.GetMeshInfos()
}

func (this *Links) ServedLinksFor(name LinkName) LinkNameSet {
	return this.links.ServedLinksFor(name)
}

func (this *Links) MeshLinksFor(name string) LinkNameSet {
	return this.meshes.MeshLinksFor(name)
}

func (this *Links) LinkInfoUpdated(logger logger.LogContext, name LinkName, access *LinkAccessInfo, dns *LinkDNSInfo) *Link {
	this.lock.Lock()
	defer this.lock.Unlock()
	old := this.links.ByName(name)
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

func (this *Links) UpdateLinkInfo(logger logger.LogContext, name LinkName, access *LinkAccessInfo, dns *LinkDNSInfo, pending bool) (*Link, bool) {
	this.lock.Lock()
	defer this.lock.Unlock()
	old := this.links.ByName(name)
	if old == nil {
		old = this.meshes.LinkByLinkName(name)
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

	if link.IsLocalLink() {
		this.links.Remove(link.Name)
		this.meshes.Add(link)
	} else {
		this.meshes.Add(link)
		this.links.Add(link)
	}
	return link
}

func (this *Links) UpdateLink(klink *api.KubeLink) (*Link, bool, error) {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.updateLink(klink)
}

func (this *Links) GetLink(name LinkName) *Link {
	return this.links.ByName(name)
}

func (this *Links) GetMeshLink(name LinkName) *Link {
	return this.meshes.LinkByLinkName(name)
}

func (this *Links) updateLink(klink *api.KubeLink) (*Link, bool, error) {
	name := DecodeLinkNameFromString(klink.Name)

	l, err := LinkForSpec(name, &klink.Spec, this.defaultport, net.ParseIP(klink.Status.Gateway))
	if err != nil {
		return nil, false, err
	}

	stale := true
	defer func() {
		if stale {
			this.stale.Add(l)
		}
	}()

	if !l.IsLocalLink() {
		m := this.meshes.ByName(name.mesh)
		if m == nil {
			return nil, true, fmt.Errorf("no local link for mesh %q", name.mesh)
		}
		cidr := tcp.CIDRNet(l.ClusterAddress)
		if !tcp.EqualCIDR(cidr, m.cidr) {
			return nil, true, fmt.Errorf("mesh cidr mismatch (mesh uses %s)", m.cidr)
		}

		if l.GatewayLink != nil {
			if this.IsGatewayLink(l.Name) {
				return nil, true, fmt.Errorf("link is gateway for %s and cannot use gateway",
					this.links.ServedLinksFor(l.Name).AddAll(this.stale.ServedLinksFor(l.Name)))
			}

			gw := this.links.ByName(*l.GatewayLink)
			if gw == nil {
				gw = this.stale.ByName(*l.GatewayLink)
				if gw != nil {
					return nil, true, fmt.Errorf("gateway link %q is stale", *l.GatewayLink)
				}
				if this.meshes.ByLinkName(*l.GatewayLink) != nil {
					return nil, true, fmt.Errorf("gateway link %q is local link", *l.GatewayLink)
				}
				return nil, true, fmt.Errorf("gateway link %q not found", *l.GatewayLink)
			}
		}
	}
	stale = false
	return this.replaceLink(l), true, nil
}

func (this *Links) RemoveLink(name LinkName) {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.links.Remove(name)
	this.stale.Remove(name)
	this.meshes.Remove(name)
}

func (this *Links) HasWireguard() bool {
	return this.links.HasWireguard()
}

func (this *Links) IsGatewayLink(name LinkName) bool {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.links.IsGatewayLink(name) || this.stale.IsGatewayLink(name)
}

func (this *Links) VisitLinks(visitor func(l *Link) bool) {
	this.links.Visit(visitor)
}

func (this *Links) VisitMeshes(visitor func(m *Mesh, l *Link) bool) {
	this.meshes.Visit(visitor)
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

	return this.links.IsGatewayNode(ifce.IP)
}

func (this *Links) LookupMeshGatewaysFor(ip net.IP) tcp.IPList {
	gateways := this.links.LookupGatewaysForMeshIP(ip)
	this.lock.RLock()
	defer this.lock.RUnlock()

	if this.gateway != nil && !gateways.Contains(this.gateway) {
		gateways = append(gateways, this.gateway)
	}
	return gateways
}

func (this *Links) GetLinkForIP(ip net.IP) *Link {
	return this.links.LookupByEgressIP(ip)
}

func (this *Links) GetLinkForClusterAddress(ip net.IP) *Link {
	return this.links.ByClusterAddress(ip)
}

func (this *Links) GetLocalAddressForClusterAddress(ip net.IP) *net.IPNet {
	m := this.GetMeshForClusterAddress(ip)
	if m == nil {
		return nil
	}
	return m.ClusterAddress()
}

func (this *Links) GetMeshForClusterAddress(ip net.IP) *Mesh {
	return this.meshes.LookupByIP(ip)
}

func (this *Links) GetLinkForEndpointHost(dnsname string) *Link {
	return this.links.ByEndpointHost(dnsname)
}

func (this *Links) getGatewayFor(l *Link) net.IP {
	gateway := this.gateway
	if gateway == nil {
		gateway = l.Gateway
	}
	return gateway
}

func (this *Links) GetRoutes(ifce *NodeInterface) Routes {
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
	for _, l := range this.links.All() {
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

// GetGatewayEgress determines the possible mesh interface egress for
// an interface or a dedicated mesh given by its cidr.
func (this *Links) GetGatewayEgress(ifce *NodeInterface, meshCIDR *net.IPNet) tcp.CIDRList {
	meshCIDR = tcp.CIDRNet(meshCIDR)

	this.lock.RLock()
	defer this.lock.RUnlock()

	// first determine all potential mesh egresses
	var meshes tcp.CIDRList
	if meshCIDR == nil {
		meshes = this.meshes.GetMeshCIDRs()
	} else {
		meshes = append(meshes, meshCIDR)
	}

	egress := tcp.CIDRList{}
	for _, l := range this.links.All() {
		if this.matchGateway(l, ifce) && this.matchMesh(l, meshCIDR) {
			for _, c := range l.Egress {
				if !meshes.ContainsCIDR(c) {
					egress = append(egress, c)
				}
			}
		}
	}
	egress = append(egress, meshes...)
	return egress
}

func (this *Links) RegisterLink(name LinkName, clusterCIDR *net.IPNet, fqdn string, cidr *net.IPNet) (*Link, error) {
	kl := &api.KubeLink{}
	kl.Name = name.String()
	kl.Spec.ClusterAddress = clusterCIDR.IP.String()
	kl.Spec.Endpoint = fqdn
	kl.Spec.CIDR = cidr.String()
	_, err := this.resource.Create(kl)
	if err != nil {
		return nil, err
	}
	l, _, err := this.UpdateLink(kl)
	return l, err
}
