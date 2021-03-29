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
	"bytes"
	"crypto/md5"
	"fmt"
	"hash"
	"net"
	"sort"
	"strings"

	"github.com/mandelsoft/kubelink/pkg/tcp"
)

const PROTO_TCP = "tcp"
const PROTO_UDP = "udp"

////////////////////////////////////////////////////////////////////////////////
// Service

type Service struct {
	Key       string
	Address   net.IP
	Mesh      string
	Ports     ServicePorts
	Endpoints ServiceEndpoints
}

func (this *Service) Normalize() {
	if this.Address != nil {
		this.Mesh = ""
	}
	ip := this.Address.To4()
	if ip != nil {
		this.Address = ip
	}
	this.Ports.Normalize()
	this.Endpoints.Normalize()
}

func (this *Service) Equal(s *Service) bool {
	if s == this {
		return true
	}
	if s == nil || this == nil {
		return false
	}

	if this.Key != s.Key {
		return false
	}

	if this.Mesh != s.Mesh {
		return false
	}

	if !tcp.EqualIP(this.Address, s.Address) {
		return false
	}

	if !this.Ports.Equal(s.Ports) {
		return false
	}

	return this.Endpoints.Equal(s.Endpoints)
}

////////////////////////////////////////////////////////////////////////////////
// service port list

type ServicePorts []ServicePort

func (this ServicePorts) Normalize() {
	if this == nil {
		return
	}
	for i := range this {
		(&this[i]).Normalize()
	}
	sort.Slice(this, this.Less)
}

func (this ServicePorts) Less(i, j int) bool {
	return this[i].Compare(&this[j]) < 0
}

func (this ServicePorts) Equal(s ServicePorts) bool {
	if len(this) != len(s) {
		return false
	}
	for i, p := range this {
		if !p.Equal(&s[i]) {
			return false
		}
	}
	return true
}

////////////////////////////////////////////////////////////////////////////////
// service port

type ServicePort struct {
	Protocol string
	Port     int32
}

func (this *ServicePort) Normalize() {
	if this.Protocol == "" {
		this.Protocol = PROTO_TCP
	} else {
		this.Protocol = strings.ToLower(this.Protocol)
	}
}

func (this *ServicePort) Compare(p *ServicePort) int {
	if this.Port < p.Port {
		return -1
	}
	if this.Port == p.Port {
		return strings.Compare(this.Protocol, p.Protocol)
	}
	return 1
}

func (this *ServicePort) Equal(p *ServicePort) bool {
	if this == p {
		return true
	}
	if this == nil || p == nil {
		return false
	}
	return this.Port == p.Port && this.Protocol == p.Protocol
}

func (this *ServicePort) String() string {
	if this == nil {
		return ""
	}
	return fmt.Sprintf("(%s port %d)", this.Protocol, this.Port)
}

////////////////////////////////////////////////////////////////////////////////
// Service Endpoint list

type ServiceEndpoints []ServiceEndpoint

func (this ServiceEndpoints) Normalize() {
	for i := range this {
		(&this[i]).Normalize()
	}
	sort.Slice(this, this.Less)
}

func (this ServiceEndpoints) Less(i, j int) bool {
	return this[i].Compare(&this[j]) < 0
}

func (this ServiceEndpoints) Equal(s ServiceEndpoints) bool {
	if len(this) != len(s) {
		return false
	}

	for i, p := range this {
		if !p.Equal(&s[i]) {
			return false
		}
	}

	return true
}

func (this ServiceEndpoints) Hash(port *ServicePort) hash.Hash {
	h := md5.New()
	if port != nil {
		h.Write(tcp.HtoNs(uint16(port.Port)))
		h.Write([]byte(port.Protocol))
	}
	for i := range this {
		this[i].AddToHash(h, port)
	}
	return h
}

////////////////////////////////////////////////////////////////////////////////
// service endpoint

type ServiceEndpoint struct {
	Address      net.IP
	PortMappings PortMappings
}

func (this *ServiceEndpoint) Normalize() {
	ip := this.Address.To4()
	if ip != nil {
		this.Address = ip
	}
	this.PortMappings.Normalize()
}

func (this *ServiceEndpoint) Compare(e *ServiceEndpoint) int {
	return bytes.Compare(this.Address, this.Address)
}

func (this *ServiceEndpoint) Equal(s *ServiceEndpoint) bool {
	if this == s {
		return true
	}
	if this == nil || s == nil {
		return false
	}
	if !this.Address.Equal(s.Address) {
		return false
	}
	return this.PortMappings.Equal(s.PortMappings)
}

func (this *ServiceEndpoint) TargetPortFor(port *ServicePort) int32 {
	if port == nil {
		return 0
	}
	for _, m := range this.PortMappings {
		if m.Port == *port {
			return m.TargetPort
		}
	}
	return port.Port
}

func (this *ServiceEndpoint) AddToHash(hash hash.Hash, port *ServicePort) {
	hash.Write(this.Address)
	if port != nil {
		for _, m := range this.PortMappings {
			if m.Port == *port {
				hash.Write(tcp.HtoNs(uint16(m.TargetPort)))
				return
			}
		}
		hash.Write(tcp.HtoNs(uint16(port.Port)))
	}
}

////////////////////////////////////////////////////////////////////////////////
// Port mapping lst

type PortMappings []PortMapping

func (this PortMappings) Normalize() {
	for i := range this {
		(&this[i]).Normalize()
	}
	sort.Slice(this, this.Less)
}

func (this PortMappings) Less(i, j int) bool {
	return this[i].Compare(&this[j]) < 0
}

func (this PortMappings) Equal(p PortMappings) bool {
	if len(this) != len(p) {
		return false
	}
	for i, e := range this {
		if !e.Equal(&p[i]) {
			return false
		}
	}
	return true
}

////////////////////////////////////////////////////////////////////////////////
// Port mapping

type PortMapping struct {
	Port       ServicePort
	TargetPort int32
}

func (this *PortMapping) Normalize() {
	this.Port.Normalize()
}

func (this *PortMapping) Compare(p *PortMapping) int {
	c := this.Port.Compare(&p.Port)
	if c != 0 {
		return c
	}
	return int(this.TargetPort) - int(this.TargetPort)
}

func (this *PortMapping) Equal(p *PortMapping) bool {
	if this == p {
		return true
	}
	if this == nil || p == nil {
		return false
	}
	return this.Port.Equal(&p.Port) && this.TargetPort == p.TargetPort
}
