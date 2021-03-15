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
	"net"
	"sync"

	"github.com/mandelsoft/kubelink/pkg/tcp"
)

type LinkIndex struct {
	lock               sync.RWMutex
	linksByName        map[LinkName]*Link
	linksByHost        map[string]*Link
	linksByClusterAddr map[string]*Link
	linksByMesh        map[string]LinkNameSet
	linkGateways       map[LinkName]LinkNameSet
	wireguard          int
}

func NewLinkIndex() *LinkIndex {
	return &LinkIndex{
		linksByName:        map[LinkName]*Link{},
		linksByHost:        map[string]*Link{},
		linksByClusterAddr: map[string]*Link{},
		linksByMesh:        map[string]LinkNameSet{},
		linkGateways:       map[LinkName]LinkNameSet{},
	}
}

func (this *LinkIndex) Add(link *Link) {
	this.lock.Lock()
	defer this.lock.Unlock()

	old := this.remove(link.Name)
	if old != nil && old.UpdatePending && !link.UpdatePending {
		link.LinkDNSInfo = old.LinkDNSInfo
		link.LinkAccessInfo = old.LinkAccessInfo
	}
	this.linksByName[link.Name] = link
	if link.ClusterAddress != nil {
		this.linksByClusterAddr[link.ClusterAddress.IP.String()] = link
	}
	if link.Host != "" {
		this.linksByHost[link.Host] = link
	}
	set := this.linksByMesh[link.Name.mesh]
	if set == nil {
		set = LinkNameSet{}
		this.linksByMesh[link.Name.mesh] = set
	}
	set.Add(link.Name)
	if link.GatewayLink != nil {
		set := this.linkGateways[*link.GatewayLink]
		if set == nil {
			set = LinkNameSet{}
			this.linkGateways[*link.GatewayLink] = set
		}
		set.Add(link.Name)
	}
	if link.IsWireguard() {
		this.wireguard++
	}
}

func (this *LinkIndex) Remove(name LinkName) {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.remove(name)
}

func (this *LinkIndex) remove(name LinkName) *Link {
	old := this.linksByName[name]
	if old == nil {
		return old
	}

	if old.GatewayLink != nil {
		set := this.linkGateways[*old.GatewayLink]
		if set != nil {
			set.Remove(name)
			if len(set) == 0 {
				delete(this.linkGateways, *old.GatewayLink)
			}
		}
	}
	set := this.linksByMesh[name.mesh]
	if set != nil {
		set.Remove(name)
		if len(set) == 0 {
			delete(this.linksByMesh, name.mesh)
		}
	}
	if old.Host != "" {
		delete(this.linksByHost, old.Host)
	}
	if old.ClusterAddress != nil {
		delete(this.linksByClusterAddr, old.ClusterAddress.IP.String())
	}
	delete(this.linksByName, name)

	if old.IsWireguard() {
		this.wireguard--
	}
	return old
}

func (this *LinkIndex) ServedLinksFor(name LinkName) LinkNameSet {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.linkGateways[name].Copy()
}

func (this *LinkIndex) All() map[LinkName]*Link {
	this.lock.RLock()
	defer this.lock.RUnlock()
	r := map[LinkName]*Link{}
	for k, v := range this.linksByName {
		r[k] = v
	}
	return r
}

func (this *LinkIndex) HasWireguard() bool {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.wireguard > 0
}

func (this *LinkIndex) ByName(name LinkName) *Link {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.linksByName[name]
}

func (this *LinkIndex) ByEndpointHost(name string) *Link {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.linksByHost[name]
}

func (this *LinkIndex) ByClusterAddress(ip net.IP) *Link {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.linksByClusterAddr[ip.String()]
}

func (this *LinkIndex) ByMesh(name string) LinkNameSet {
	this.lock.RLock()
	set := this.linksByMesh[name]
	this.lock.RUnlock()
	if set == nil {
		return LinkNameSet{}
	}
	return set.Copy()
}

func (this *LinkIndex) LookupByEgressIP(ip net.IP) *Link {
	this.lock.RLock()
	defer this.lock.RUnlock()

	if l := this.linksByClusterAddr[ip.String()]; l != nil {
		return l
	}
	for _, l := range this.linksByName {
		if l.AcceptIP(ip) && l.GatewayLink == nil {
			return l
		}
	}
	return nil
}

func (this *LinkIndex) LookupGatewaysForMeshIP(ip net.IP) tcp.IPList {
	this.lock.RLock()
	defer this.lock.RUnlock()

	var r tcp.IPList
	for _, l := range this.linksByName {
		if l.ClusterAddress.Contains(ip) {
			if l.Gateway != nil {
				if !r.Contains(l.Gateway) {
					r = append(r, l.Gateway)
				}
			}
		}
	}
	return r
}

func (this *LinkIndex) IsGatewayNode(ip net.IP) bool {
	this.lock.RLock()
	defer this.lock.RUnlock()

	for _, l := range this.linksByName {
		if l.ClusterAddress.Contains(ip) {
			if l.Gateway != nil && l.Gateway.Equal(ip) {
				return true
			}
		}
	}
	return false
}

func (this *LinkIndex) IsGatewayLink(name LinkName) bool {
	this.lock.RLock()
	defer this.lock.RUnlock()
	gws := this.linkGateways[name]
	return gws != nil && len(gws) != 0
}

func (this *LinkIndex) Visit(visitor func(l *Link) bool) {
	this.lock.RLock()
	links := make([]*Link, len(this.linksByName))
	i := 0
	for _, l := range this.linksByName {
		links[i] = l
		i++
	}
	this.lock.RUnlock()
	for _, l := range links {
		if !visitor(l) {
			break
		}
	}
}
