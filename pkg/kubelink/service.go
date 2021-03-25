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
	Ports     []ServicePort
	Endpoints ServiceEndpoints
}

func (this *Service) Normalize() {
	ip := this.Address.To4()
	if ip != nil {
		this.Address = ip
	}
	for i := range this.Ports {
		(&this.Ports[i]).Normalize()
	}
	this.Endpoints.Normalize()
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

func (this *ServicePort) String() string {
	if this == nil {
		return ""
	}
	return fmt.Sprintf("(%s port %d)", this.Protocol, this.Port)
}

////////////////////////////////////////////////////////////////////////////////
// service endpoint

type ServiceEndpoint struct {
	Address      net.IP
	PortMappings []PortMapping
}

func (this *ServiceEndpoint) Normalize() {
	ip := this.Address.To4()
	if ip != nil {
		this.Address = ip
	}
	for i := range this.PortMappings {
		(&this.PortMappings[i]).Normalize()
	}
}

func (this *ServiceEndpoint) PortSuffix(port *ServicePort) string {
	if port == nil {
		return ""
	}
	for _, m := range this.PortMappings {
		if m.Port == *port {
			return fmt.Sprintf(":%d", m.TargetPort)
		}
	}
	return fmt.Sprintf(":%d", port.Port)
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
// Port mapping

type PortMapping struct {
	Port       ServicePort
	TargetPort int32
}

func (this *PortMapping) Normalize() {
	this.Port.Normalize()
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

func (this ServiceEndpoints) Len() int {
	return len(this)
}
func (this ServiceEndpoints) Less(i, j int) bool {
	return bytes.Compare(this[i].Address, this[j].Address) < 0
}
func (this ServiceEndpoints) Swap(i, j int) {
	this[i], this[j] = this[j], this[i]
}
