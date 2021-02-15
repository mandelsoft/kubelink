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
	"net"
	"sync"
)

type Mesh interface {
	GetId() string
	GetDomain() string
	GetCidr() *net.IPNet

	GetMemberById(id string) Member
	GetMemberByIP(ip net.IP) Member
}

func NewMesh(id string, domain string, cidr *net.IPNet) Mesh {
	return &mesh{
		id:     id,
		domain: domain,
		cidr:   cidr,

		memberById: map[string]*mesh{},
		memberByIP: map[string]*mesh{},
	}
}

type mesh struct {
	lock   sync.Mutex
	id     string
	cidr   *net.IPNet
	domain string

	memberById map[string]*mesh
	memberByIP map[string]*mesh
}

var _ Mesh = &mesh{}

func (this *mesh) GetId() string {
	return this.id
}

func (this *mesh) GetCidr() *net.IPNet {
	return this.cidr
}

func (this *mesh) GetDomain() string {
	return this.domain
}

func (this *mesh) GetMemberById(id string) Member {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.memberById[id]
}

func (this *mesh) GetMemberByIP(ip net.IP) Member {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.memberByIP[ip.String()]
}
