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

package database

import (
	"crypto/x509"
	"fmt"
	"net"
	"sync"

	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/gardener/controller-manager-library/pkg/utils"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
)

type Mesh interface {
	GetRevision() Revision

	GetClusterObjectKey() resources.ClusterObjectKey
	GetName() resources.ObjectName
	GetId() string
	GetNamespace() string
	GetDomain() string
	GetCidr() *net.IPNet
	GetIPAM() *resources.ClusterObjectKey

	GetCertPool() *x509.CertPool
	GetVerifyOpts() *x509.VerifyOptions

	GetState() string
	GetMessage() string

	GetMembers() utils.StringSet
	GetMemberByName(name resources.ObjectName) Member
	GetMemberById(id string) Member
	GetMemberByIP(ip net.IP) Member

	UpdateMember(member resources.Object) error
	DeleteByName(name resources.ObjectName)
}

func NewMesh(key resources.ClusterObjectKey, id string, namespace string, domain string, cidr *net.IPNet) *mesh {
	return &mesh{
		key:       key,
		id:        id,
		namespace: namespace,
		domain:    domain,
		cidr:      cidr,

		memberByName: map[resources.ObjectName]*member{},
		memberById:   map[string]*member{},
		memberByIP:   map[string]*member{},
	}
}

type mesh struct {
	lock      sync.Mutex
	revision  Revision
	key       resources.ClusterObjectKey
	id        string
	namespace string
	cidr      *net.IPNet
	domain    string
	state     string
	message   string
	pool      *x509.CertPool
	verify    *x509.VerifyOptions
	ipam      *resources.ClusterObjectKey

	memberByName map[resources.ObjectName]*member
	memberById   map[string]*member
	memberByIP   map[string]*member
}

var _ Mesh = &mesh{}

func ToMesh(m *mesh) Mesh {
	if m == nil {
		return nil
	}
	return m
}

func (this *mesh) GetRevision() Revision {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.revision
}

func (this *mesh) GetClusterObjectKey() resources.ClusterObjectKey {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.key
}

func (this *mesh) GetName() resources.ObjectName {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.key.ObjectName()
}

func (this *mesh) GetId() string {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.id
}

func (this *mesh) GetNamespace() string {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.namespace
}

func (this *mesh) GetCidr() *net.IPNet {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.cidr
}

func (this *mesh) GetIPAM() *resources.ClusterObjectKey {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.ipam
}

func (this *mesh) GetDomain() string {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.domain
}

func (this *mesh) GetState() string {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.state
}

func (this *mesh) GetMessage() string {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.message
}

func (this *mesh) GetCertPool() *x509.CertPool {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.pool
}

func (this *mesh) GetMembers() utils.StringSet {
	this.lock.Lock()
	defer this.lock.Unlock()
	return utils.StringKeySet(this.memberById)
}

func (this *mesh) GetMemberByName(name resources.ObjectName) Member {
	this.lock.Lock()
	defer this.lock.Unlock()
	return ToMember(this.memberByName[name])
}

func (this *mesh) GetMemberById(id string) Member {
	this.lock.Lock()
	defer this.lock.Unlock()
	return ToMember(this.memberById[id])
}

func (this *mesh) GetMemberByIP(ip net.IP) Member {
	this.lock.Lock()
	defer this.lock.Unlock()
	return ToMember(this.memberByIP[ip.String()])
}

func (this *mesh) UpdateMember(obj resources.Object) error {
	this.lock.Lock()
	defer this.lock.Unlock()

	member := obj.Data().(*api.MeshMember)

	var routes []Route
	for _, s := range member.Spec.Routes {
		r, err := ParseRoute(s)
		if err != nil {
			return err
		}
		routes = append(routes, r)
	}

	var addr *net.IPNet
	if member.Status.Address != "" {
		ip := net.ParseIP(member.Status.Address)
		if ip == nil {
			return fmt.Errorf("invalid ip %q", member.Status.Address)
		}
		cidr := *this.cidr
		cidr.IP = ip
		addr = &cidr
	}

	var pub *wgtypes.Key
	if member.Spec.PublicKey != "" {
		key, err := wgtypes.ParseKey(member.Spec.PublicKey)
		if err != nil {
			return err
		}
		pub = &key
	}

	var gateway resources.ObjectName
	if member.Spec.Gateway != nil {
		gateway = member.Spec.Gateway.RelativeTo(obj)
	}

	current := this.memberByName[obj.ObjectName()]
	if current == nil {
		if this.memberById[member.Spec.Identity] != nil {
			// TODO: check creation timestamp to identify first one
			return fmt.Errorf("duplicate member id %q", member.Spec.Identity)
		}
		current = NewMember(obj.ClusterKey(), member.Spec.Identity)
		name := current.name.ObjectName()
		for _, m := range this.memberByName {
			if EqualsObjectName(m.gateway, name) {
				current.gatewayFor.Add(m.id)
			}
		}
		this.memberByName[obj.ObjectName()] = current
	} else {
		delete(this.memberById, current.id)
		if current.address != nil {
			delete(this.memberByIP, current.address.String())
		}
		if current.gateway != nil {
			gw:=this.memberByName[current.gateway]
			if gw!=nil {
				gw.gatewayFor.Remove(current.id)
			}
		}
	}

	current.routes = routes
	current.publicKey = pub
	current.address = addr
	current.gateway = gateway
	current.created = obj.GetCreationTimestamp().Time
    current.endpoints = member.Spec.Endpoint

	if member.Spec.Identity != "" {
		this.memberById[member.Spec.Identity] = current
	}
	if addr != nil {
		this.memberByIP[addr.String()] = current
	}
	if current.gateway != nil {
		gw := this.memberByName[current.gateway]
		if gw != nil {
			gw.gatewayFor.Add(current.id)
		}
	}
	if r:=Revision(obj.GetResourceVersion()); r.After(this.revision) {
		this.revision=r
	}
	return nil
}

func (this *mesh) DeleteByName(name resources.ObjectName) {
	this.lock.Lock()
	defer this.lock.Unlock()

	old := this.memberByName[name]
	if old != nil {
		delete(this.memberByName, name)
		if this.memberById[old.id] == old {
			delete(this.memberById, old.id)
		}
		addr := old.GetAddress()
		if addr != nil && this.memberByIP[addr.String()] == old {
			delete(this.memberByIP, addr.String())
		}
	}
}

func (this *mesh) GetVerifyOpts() *x509.VerifyOptions {
	if this.verify == nil {
		return nil
	}
	verify := *this.verify
	return &verify
}

func (this *mesh) SetPool(pool *x509.CertPool) {
	if pool == nil {
		pool, _ = x509.SystemCertPool()
	}
	if pool != nil {
		this.verify = &x509.VerifyOptions{
			Roots:     pool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
	} else {
		this.verify = nil
	}
	this.pool = pool
}

func EqualsObjectName(a,b resources.ObjectName) bool {
	if a==b {
		return true
	}
	if a==nil || b==nil {
		return false
	}
	return resources.EqualsObjectName(a,b)
}