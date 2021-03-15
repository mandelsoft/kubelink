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

type mesh struct {
	link *Link
	info *Mesh
}

type MeshIndex struct {
	lock         sync.RWMutex
	meshesByLink map[LinkName]*mesh
	meshesByName map[string]*mesh
	meshesByCIDR map[string]*mesh
	meshesByAddr map[string]*mesh
	meshlinks    map[string]LinkNameSet
	defaultMesh  *Link
}

func NewMeshIndex() *MeshIndex {
	return &MeshIndex{
		meshesByLink: map[LinkName]*mesh{},
		meshesByName: map[string]*mesh{},
		meshesByCIDR: map[string]*mesh{},
		meshesByAddr: map[string]*mesh{},
		meshlinks:    map[string]LinkNameSet{},
		defaultMesh:  nil,
	}
}

func (this *MeshIndex) SetDefaultMesh(link *Link) {
	this.lock.Lock()
	defer this.lock.Unlock()
	old := this.meshesByName[DEFAULT_MESH]
	if old != nil && old.link == this.defaultMesh {
		this.remove(old.link.Name)
	}
	if link == nil {
		this.defaultMesh = nil
	} else {
		this.defaultMesh = link
		this.add(link)
	}
}

func (this *MeshIndex) Add(link *Link) {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.add(link)
}

func (this *MeshIndex) add(link *Link) {
	this.remove(link.Name)

	if !link.IsLocalLink() {
		set := this.meshlinks[link.Name.mesh]
		if set == nil {
			set = LinkNameSet{}
			this.meshlinks[link.Name.mesh] = set
		}
		set.Add(link.Name)
		return
	}

	m := &mesh{
		link: link,
		info: NewMeshInfo(link),
	}

	this.meshesByLink[link.Name] = m
	this.meshesByName[m.info.name] = m
	if m.info.cidr != nil {
		this.meshesByCIDR[m.info.cidr.String()] = m
	}
	if m.info.clusterAddress != nil {
		this.meshesByAddr[m.info.clusterAddress.IP.String()] = m
	}
}

func (this *MeshIndex) Remove(name LinkName) {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.remove(name)
}

func (this *MeshIndex) RemoveByName(name string) {
	this.lock.Lock()
	defer this.lock.Unlock()
	if old := this.meshesByName[name]; old != nil {
		this.remove(old.link.Name)
	}
}

func (this *MeshIndex) remove(name LinkName) {
	set := this.meshlinks[name.mesh]
	if set != nil {
		set.Remove(name)
		if len(set) == 0 {
			delete(this.meshlinks, name.mesh)
		}
	}

	old := this.meshesByLink[name]
	if old == nil {
		return
	}

	if old.info.clusterAddress != nil {
		delete(this.meshesByAddr, old.info.clusterAddress.IP.String())
	}
	if old.info.cidr != nil {
		delete(this.meshesByCIDR, old.info.cidr.String())
	}
	delete(this.meshesByName, name.name)
	delete(this.meshesByLink, name)
}

func (this *MeshIndex) MeshLinksFor(name string) LinkNameSet {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.meshlinks[name].Copy()
}

func (this *MeshIndex) All() map[string]*Mesh {
	this.lock.RLock()
	defer this.lock.RUnlock()
	r := map[string]*Mesh{}
	for k, v := range this.meshesByName {
		r[k] = v.info
	}
	return r
}

func (this *MeshIndex) ByName(name string) *Mesh {
	this.lock.RLock()
	defer this.lock.RUnlock()

	m := this.meshesByName[name]
	if m == nil {
		return nil
	}
	return m.info
}

func (this *MeshIndex) LinkByName(name string) *Link {
	this.lock.RLock()
	defer this.lock.RUnlock()

	m := this.meshesByName[name]
	if m == nil {
		return nil
	}
	return m.link
}

func (this *MeshIndex) ByLinkName(name LinkName) *Mesh {
	this.lock.RLock()
	defer this.lock.RUnlock()

	m := this.meshesByLink[name]
	if m == nil {
		return nil
	}
	return m.info
}

func (this *MeshIndex) LinkByLinkName(name LinkName) *Link {
	this.lock.RLock()
	defer this.lock.RUnlock()

	m := this.meshesByLink[name]
	if m == nil {
		return nil
	}
	return m.link
}

func (this *MeshIndex) ByLocalAddress(ip net.IP) *Mesh {
	this.lock.RLock()
	defer this.lock.RUnlock()

	m := this.meshesByAddr[ip.String()]
	if m == nil {
		return nil
	}
	return m.info
}

func (this *MeshIndex) ByCIDR(cidr *net.IPNet) *Mesh {
	if cidr == nil {
		return nil
	}
	cidr = tcp.CIDRNet(cidr)

	this.lock.RLock()
	defer this.lock.RUnlock()

	m := this.meshesByCIDR[cidr.String()]
	if m == nil {
		return nil
	}
	return m.info
}

func (this *MeshIndex) LinkByCIDR(cidr *net.IPNet) *Link {
	cidr = tcp.CIDRNet(cidr)

	this.lock.RLock()
	defer this.lock.RUnlock()

	m := this.meshesByCIDR[cidr.String()]
	if m == nil {
		return nil
	}
	return m.link
}

func (this *MeshIndex) GetMeshCIDRs() tcp.CIDRList {
	this.lock.RLock()
	defer this.lock.RUnlock()
	r := tcp.CIDRList{}
	for _, v := range this.meshesByLink {
		r = append(r, v.info.CIDR())
	}
	return r
}

func (this *MeshIndex) GetMeshLinks() map[LinkName]*Link {
	this.lock.RLock()
	defer this.lock.RUnlock()
	r := map[LinkName]*Link{}
	for k, v := range this.meshesByLink {
		r[k] = v.link
	}
	return r
}

func (this *MeshIndex) GetMeshInfos() map[string]*Mesh {
	this.lock.RLock()
	defer this.lock.RUnlock()
	r := map[string]*Mesh{}
	for _, m := range this.meshesByName {
		r[m.info.name] = m.info
	}
	return r
}

func (this *MeshIndex) LookupByIP(ip net.IP) *Mesh {
	this.lock.RLock()
	defer this.lock.RUnlock()
	for _, m := range this.meshesByName {
		if m.info.CIDR().Contains(ip) {
			return m.info
		}
	}
	return nil
}

func (this *MeshIndex) Visit(visitor func(m *Mesh, l *Link) bool) {
	this.lock.RLock()
	elems := make([]*mesh, len(this.meshesByName))
	i := 0
	for _, l := range this.meshesByName {
		elems[i] = l
		i++
	}
	this.lock.RUnlock()
	for _, m := range elems {
		if !visitor(m.info, m.link) {
			break
		}
	}
}
