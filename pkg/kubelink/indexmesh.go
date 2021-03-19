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
	"sync"
	"time"

	"github.com/mandelsoft/kubelink/pkg/tcp"
)

type StaleMeshIndex struct {
	lock   sync.RWMutex
	meshes map[string]map[LinkName]time.Time
}

func NewStaleMeshIndex() *StaleMeshIndex {
	return &StaleMeshIndex{meshes: map[string]map[LinkName]time.Time{}}
}

func (this *StaleMeshIndex) Add(l *Link) {
	this.lock.Lock()
	defer this.lock.Unlock()

	this.remove(l.Name)

	if !l.IsLocalLink() {
		return
	}
	set := this.meshes[l.Name.mesh]
	if set == nil {
		set = map[LinkName]time.Time{}
		this.meshes[l.Name.mesh] = set
	}
	set[l.Name] = l.CreationTime
}

func (this *StaleMeshIndex) Remove(name LinkName) {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.remove(name)
}

func (this *StaleMeshIndex) remove(name LinkName) {
	set := this.meshes[name.mesh]
	if set != nil {
		delete(set, name)
		if len(set) == 0 {
			delete(this.meshes, name.mesh)
		}
	}
}

func (this *StaleMeshIndex) ByName(name string) *LinkName {
	this.lock.RLock()
	defer this.lock.RUnlock()

	var found *LinkName
	if set := this.meshes[name]; len(set) > 0 {
		first := time.Now()
		for n, t := range set {
			if t.Before(first) {
				tmp := n
				found = &tmp
			}
		}
	}
	return found
}

////////////////////////////////////////////////////////////////////////////////

type mesh struct {
	link          *Link
	info          *Mesh
	deletePending bool
}

type MeshIndex struct {
	lock         sync.RWMutex
	meshesByLink map[LinkName]*mesh
	meshesByName map[string]*mesh
	meshesByCIDR map[string]*mesh
	meshesByAddr map[string]*mesh
	defaultMesh  *Link
}

func NewMeshIndex() *MeshIndex {
	return &MeshIndex{
		meshesByLink: map[LinkName]*mesh{},
		meshesByName: map[string]*mesh{},
		meshesByCIDR: map[string]*mesh{},
		meshesByAddr: map[string]*mesh{},
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
		fmt.Printf("clearing default mesh\n")
		this.defaultMesh = nil
	} else {
		fmt.Printf("settings default mesh\n")
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
	old := this.meshesByLink[link.Name]

	this.remove(link.Name)

	if !link.IsLocalLink() {
		return
	}
	m := &mesh{
		link: link,
		info: NewMeshInfo(link, old != nil && old.deletePending),
	}

	this.meshesByLink[link.Name] = m
	this.meshesByName[m.info.Name()] = m
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
	delete(this.meshesByName, name.mesh)
	delete(this.meshesByLink, name)
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
		r[m.info.Name()] = m.info
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

func (this *MeshIndex) MarkLinkForDeletion(name LinkName) {
	this.lock.RLock()
	defer this.lock.RUnlock()

	m := this.meshesByLink[name]
	if m != nil {
		m.deletePending = true
	}
}

func (this *MeshIndex) IsDeletePending(name string) bool {
	this.lock.RLock()
	defer this.lock.RUnlock()

	m := this.meshesByName[name]
	return m != nil && m.info.deletePending
}
