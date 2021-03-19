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

	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/vishvananda/netlink"

	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

// links is the unsynchronized internal implementation of the Links interface
// externally the synced wrapper is used, that adds locking
// it also used the internal version to pass it to synchronized functions executed
// via the Locked method
type links struct {
	resource    resources.Interface
	initialized bool

	defaultport int
	serviceCIDR *net.IPNet
	gateway     net.IP

	*linksdata
}

var _ Links = &links{}

////////////////////////////////////////////////////////////////////////////////
// linksdata provides basic synced data structurea and forwarded method
// this part can be used in unsynched and synced implementations of
// the Links interface

type linksdata struct {
	links       *LinkIndex
	stalelinks  *LinkIndex
	meshes      *MeshIndex
	stalemeshes *StaleMeshIndex
}

func newData() *linksdata {
	return &linksdata{
		links:       NewLinkIndex(),
		stalelinks:  NewLinkIndex(),
		meshes:      NewMeshIndex(),
		stalemeshes: NewStaleMeshIndex(),
	}
}

func (this *linksdata) SetDefaultMesh(clusterName string, clusterAddress *net.IPNet, meshDNS LinkDNSInfo) {
	defaultMesh := &Link{
		Name:           NewLinkName(DEFAULT_MESH, clusterName),
		ClusterAddress: clusterAddress,
		Endpoint:       EP_LOCAL,
	}
	defaultMesh.LinkDNSInfo = meshDNS
	this.meshes.SetDefaultMesh(defaultMesh)
}

func (this *linksdata) HasWireguard() bool {
	return this.links.HasWireguard()
}

////////////////////////////////////////////////////////////////////////////////

func (this *linksdata) GetLinks() map[LinkName]*Link {
	return this.links.All()
}

func (this *linksdata) GetLink(name LinkName) *Link {
	return this.links.ByName(name)
}

func (this *linksdata) ServedLinksFor(name LinkName) LinkNameSet {
	return this.links.ServedLinksFor(name)
}

func (this *linksdata) VisitLinks(visitor func(l *Link) bool) {
	this.links.Visit(visitor)
}

func (this *linksdata) GetLinkForIP(ip net.IP) *Link {
	return this.links.LookupByEgressIP(ip)
}

func (this *linksdata) GetLinkForClusterAddress(ip net.IP) *Link {
	return this.links.ByClusterAddress(ip)
}

func (this *linksdata) GetLinkForEndpointHost(dnsname string) *Link {
	return this.links.ByEndpointHost(dnsname)
}

////////////////////////////////////////////////////////////////////////////////

func (this *linksdata) GetMesh(name string) *Mesh {
	return this.meshes.ByName(name)
}

func (this *linksdata) GetStaleMesh(name string) *LinkName {
	return this.stalemeshes.ByName(name)
}

func (this *linksdata) GetMeshByLinkName(name LinkName) *Mesh {
	return this.meshes.ByLinkName(name)
}

func (this *linksdata) GetMeshLink(name LinkName) *Link {
	return this.meshes.LinkByLinkName(name)
}

func (this *linksdata) GetMeshLinks() map[LinkName]*Link {
	return this.meshes.GetMeshLinks()
}

func (this *linksdata) GetMeshInfos() map[string]*Mesh {
	return this.meshes.GetMeshInfos()
}

func (this *linksdata) RemoveMesh(name string) {
	this.meshes.RemoveByName(name)
}

func (this *linksdata) MarkForDeletion(name LinkName) {
	this.meshes.MarkLinkForDeletion(name)
}

func (this *linksdata) VisitMeshes(visitor func(m *Mesh, l *Link) bool) {
	this.meshes.Visit(visitor)
}

func (this *linksdata) LookupClusterAddressByMeshAddress(ip net.IP) *net.IPNet {
	m := this.LookupMeshByMeshAddress(ip)
	if m == nil {
		return nil
	}
	return m.ClusterAddress()
}

func (this *linksdata) LookupMeshByMeshAddress(ip net.IP) *Mesh {
	return this.meshes.LookupByIP(ip)
}

////////////////////////////////////////////////////////////////////////////////
// internal methods, always called synchronized

func (this *links) getGatewayFor(l *Link) net.IP {
	gateway := this.gateway
	if gateway == nil {
		gateway = l.Gateway
	}
	return gateway
}

func (this *links) matchGateway(l *Link, ifce *NodeInterface) bool {
	if ifce == nil {
		return true
	}
	gateway := this.getGatewayFor(l)
	return gateway != nil && gateway.Equal(ifce.IP)
}

func (this *links) matchMesh(l *Link, mesh *net.IPNet) bool {
	return mesh == nil || mesh.Contains(l.ClusterAddress.IP)
}

func (this *links) setupLinks(logger logger.LogContext, kind string, list []resources.Object, cond func(*api.KubeLink) bool) {
	last := 0

	logger.Infof("setup %s links", kind)
	for len(list) > 0 && len(list) != last {
		logger.Infof("  checking %d entries", len(list))
		stale := []resources.Object{}
		last = len(list)
		for _, l := range list {
			o := l.Data().(*api.KubeLink)
			if cond != nil && cond(o) {
				link, valid, redo, err := this.UpdateLink(o)
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
				if redo != nil {
					stale = append(stale, l)
				}
			}
		}
		list = stale
	}
	for _, l := range list {
		logger.Infof("  stale %s %s", kind, l.ObjectName())
	}
}

////////////////////////////////////////////////////////////////////////////////
// requiring locks -> called in synched

func (this *links) Setup(logger logger.LogContext, list []resources.Object) {
	if this.initialized {
		return
	}
	this.initialized = true
	// first setup meshes (LocalLinks)
	this.setupLinks(logger, "mesh", list, func(l *api.KubeLink) bool { return l.Spec.Endpoint == EP_LOCAL })
	// the setup foreign links
	this.setupLinks(logger, "node", list, func(l *api.KubeLink) bool { return l.Spec.Endpoint != EP_LOCAL })
}

////////////////////////////////////////////////////////////////////////////////

func (this *links) SetGateway(ip net.IP) {
	this.gateway = ip
}

func (this *links) GetGateway() net.IP {
	return this.gateway
}

////////////////////////////////////////////////////////////////////////////////

func (this *links) LinkInfoUpdated(logger logger.LogContext, name LinkName, access *LinkAccessInfo, dns *LinkDNSInfo) *Link {
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
			return this.ReplaceLink(&new)
		}
	}
	return old
}

func (this *links) UpdateLinkInfo(logger logger.LogContext, name LinkName, access *LinkAccessInfo, dns *LinkDNSInfo, pending bool) (*Link, bool) {
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
			return this.ReplaceLink(&new), true
		}
	}
	return old, false
}

////////////////////////////////////////////////////////////////////////////////

func (this *links) ReplaceLink(link *Link) *Link {
	this.stalelinks.Remove(link.Name)
	this.stalemeshes.Remove(link.Name)
	this.meshes.Add(link)
	this.links.Add(link)
	return link
}

func linkErr(msg string, args ...interface{}) (*Link, bool, *Link, error) {
	return nil, true, nil, fmt.Errorf(msg, args...)
}

func (this *links) UpdateLink(klink *api.KubeLink) (*Link, bool, *Link, error) {
	name := DecodeLinkNameFromString(klink.Name)

	l, err := LinkForSpec(name, klink.CreationTimestamp.Time, &klink.Spec, this.defaultport, net.ParseIP(klink.Status.Gateway))
	if err != nil {
		return nil, false, nil, err
	}

	stale := true
	var redo *Link

	defer func() {
		if stale {
			if l.IsLocalLink() {
				this.stalemeshes.Add(l)
			} else {
				this.stalelinks.Add(l)
			}
		}
	}()

	m := this.meshes.ByName(name.mesh)
	if !l.IsLocalLink() {
		if m == nil {
			return linkErr("no local link for mesh %q", name.mesh)
		}
		cidr := tcp.CIDRNet(l.ClusterAddress)
		if !tcp.EqualCIDR(cidr, m.cidr) {
			return linkErr("mesh cidr mismatch (mesh uses %s)", m.cidr)
		}

		if l.GatewayLink != nil {
			if this.IsGatewayLink(l.Name) {
				return linkErr("link is gateway for %s and cannot use gateway",
					this.links.ServedLinksFor(l.Name).AddAll(this.stalelinks.ServedLinksFor(l.Name)))
			}

			gw := this.links.ByName(*l.GatewayLink)
			if gw == nil {
				gw = this.stalelinks.ByName(*l.GatewayLink)
				if gw != nil {
					return nil, true, nil, fmt.Errorf("gateway link %q is stale", *l.GatewayLink)
				}
				if this.meshes.ByLinkName(*l.GatewayLink) != nil {
					return linkErr("gateway link %q is local link", *l.GatewayLink)
				}
				return linkErr("gateway link %q not found", *l.GatewayLink)
			}
		}
	} else {
		if m != nil && m.name != name {
			ml := this.meshes.LinkByName(m.Name())
			if ml.CreationTime.Before(l.CreationTime) {
				return linkErr("mesh %q already defined by local link %q", name.Mesh(), m.name)
			} else {
				this.RemoveLink(ml.Name)
				redo = ml
			}
		}
	}

	stale = false
	link := this.ReplaceLink(l)
	if !link.IsLocalLink() {
		if klink.GetDeletionTimestamp() != nil {
			this.MarkForDeletion(link.Name)
		}
	}
	return link, true, redo, nil
}

func (this *links) GetMeshMembersFor(name string) LinkNameSet {
	return this.links.MeshLinksFor(name).AddAll(this.stalelinks.MeshLinksFor(name))
}

func (this *links) RemoveLink(name LinkName) {
	this.links.Remove(name)
	this.stalelinks.Remove(name)
	this.meshes.Remove(name)
	this.stalemeshes.Remove(name)
}

func (this *links) IsGatewayLink(name LinkName) bool {
	return this.links.IsGatewayLink(name) || this.stalelinks.IsGatewayLink(name)
}

func (this *links) IsGateway(ifce *NodeInterface) bool {
	if ifce == nil {
		return false
	}
	if this.gateway != nil {
		if this.gateway.Equal(ifce.IP) {
			return true
		}
	} else {
	}

	return this.links.IsGatewayNode(ifce.IP)
}

func (this *links) LookupMeshGatewaysFor(ip net.IP) tcp.IPList {
	gateways := this.links.LookupGatewaysForMeshIP(ip)

	if this.gateway != nil && !gateways.Contains(this.gateway) {
		gateways = append(gateways, this.gateway)
	}
	return gateways
}

////////////////////////////////////////////////////////////////////////////////

func (this *links) GetRoutes(ifce *NodeInterface) Routes {
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
			meshCidr := tcp.CIDRNet(l.ClusterAddress)
			for _, c := range l.Egress {
				if !tcp.ContainsCIDR(meshCidr, c) {
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
			}
			r := netlink.Route{
				Dst:       meshCidr,
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

func (this *links) GetRoutesToLink(ifce *NodeInterface, link netlink.Link) Routes {
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

// GetGatewayEgress determines the possible mesh interface egress for
// an interface or a dedicated mesh given by its cidr.
func (this *links) GetGatewayEgress(ifce *NodeInterface, meshCIDR *net.IPNet) tcp.CIDRList {
	meshCIDR = tcp.CIDRNet(meshCIDR)

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

func (this *links) RegisterLink(name LinkName, clusterCIDR *net.IPNet, fqdn string, cidr *net.IPNet) (*Link, error) {
	kl := &api.KubeLink{}
	kl.Name = name.String()
	kl.Spec.ClusterAddress = clusterCIDR.IP.String()
	kl.Spec.Endpoint = fqdn
	kl.Spec.CIDR = cidr.String()
	_, err := this.resource.Create(kl)
	if err != nil {
		return nil, err
	}
	l, _, _, err := this.UpdateLink(kl)
	return l, err
}

func (this *links) Locked(f func(Links) error) error {
	return f(this)
}
