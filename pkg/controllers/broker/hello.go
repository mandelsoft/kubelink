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

package broker

import (
	"fmt"
	"net"
	"sync"

	"github.com/gardener/controller-manager-library/pkg/logger"

	"github.com/mandelsoft/kubelink/pkg/tcp"
)

const EXT_DNS = 1

type ConnectionHelloExtensionHandler interface {
	Parse(id byte, data []byte) (ConnectionHelloExtension, error)
	Add(hello *ConnectionHello, mux *Mux)
}

type ConnectionHelloExtension interface {
	Id() byte
	Data() []byte
}

var lock sync.RWMutex
var registry = map[byte]ConnectionHelloExtensionHandler{}

func RegisterExtension(id byte, c ConnectionHelloExtensionHandler) {
	lock.Lock()
	defer lock.Unlock()
	registry[id] = c
}

func GetExtension(id byte, data []byte) (ConnectionHelloExtension, error) {
	lock.RLock()
	defer lock.RUnlock()
	c := registry[id]
	if c == nil {
		return nil, nil
	}
	return c.Parse(id, data)
}

////////////////////////////////////////////////////////////////////////////////

type ConnectionHello struct {
	ConnectionHelloHeader
	Extensions map[byte]ConnectionHelloExtension
	Raw        map[byte][]byte
}

func NewConnectionHello() *ConnectionHello {
	return &ConnectionHello{
		Extensions: map[byte]ConnectionHelloExtension{},
		Raw:        map[byte][]byte{},
	}
}
func ParseConnectionHello(logger logger.LogContext, header *ConnectionHelloHeader, data []byte) (*ConnectionHello, error) {
	if int(header.GetExtensionLength()) != len(data) {
		return nil, fmt.Errorf("data too short: required %d, but found %d", int(header.GetExtensionLength()), len(data))
	}
	hello := NewConnectionHello()
	hello.ConnectionHelloHeader = *header
	start := 0

	for start < len(data) {
		if len(data)-start < 3 {
			return nil, fmt.Errorf("data too short: next extesion requires at least 3 bytes, but found %d", len(data)-start)
		}
		id := data[start]
		el := int(tcp.NtoHs(data[start+1:]))
		if len(data)-start-3 < el {
			return nil, fmt.Errorf("data too short: next extesion %d requires at least %d bytes, but found %d", id, el, len(data)-start-3)
		}
		raw := data[start+3 : start+3+el]
		hello.Raw[id] = raw
		ext, err := GetExtension(id, raw)
		if err != nil {
			logger.Errorf("extension %d: %s", id, err)
		} else {
			if ext != nil {
				hello.Extensions[id] = ext
			}
		}
		start = start + 3 + el
	}
	return hello, nil
}

func (this *ConnectionHello) Data() []byte {
	var ext []byte

	for _, e := range this.Extensions {
		this.Raw[e.Id()] = e.Data()
	}
	for id, data := range this.Raw {
		ext = append(ext, id)
		ext = append(ext, tcp.HtoNs(uint16(len(data)))...)
		ext = append(ext, data...)
	}
	this.ConnectionHelloHeader.SetExtensionLength(uint16(len(ext)))
	return append(this.ConnectionHelloHeader[:], ext...)
}

type ConnectionHelloHeader [net.IPv6len * 5]byte

func (this *ConnectionHelloHeader) setAddress(start int, ip net.IP) {
	copy(this[start:start+net.IPv6len], ip.To16())
}

func (this *ConnectionHelloHeader) setCIDR(start int, cidr *net.IPNet) {
	this.setAddress(start, cidr.IP)
	copy(this[start+net.IPv6len:start+net.IPv6len*2], net.IP(cidr.Mask).To16())
}

func (this *ConnectionHelloHeader) getAddress(start int) net.IP {
	return net.IP(this[start : start+net.IPv6len])
}

func (this *ConnectionHelloHeader) getCIDR(start int) *net.IPNet {
	ip := this.getAddress(start)
	if ip.To4() == nil {
		return &net.IPNet{
			IP:   ip,
			Mask: net.IPMask(this[start+net.IPv6len : start+net.IPv6len*2]),
		}

	} else {
		return &net.IPNet{
			IP:   ip,
			Mask: net.IPMask(this[start+net.IPv6len+net.IPv6len-net.IPv4len : start+net.IPv6len*2]),
		}
	}
}

func (this *ConnectionHelloHeader) SetExtensionLength(len uint16) {
	copy(this[net.IPv6len*5-2:], tcp.HtoNs(len))
}

func (this *ConnectionHelloHeader) GetExtensionLength() uint16 {
	return tcp.NtoHs(this[net.IPv6len*5-2:])
}

func (this *ConnectionHelloHeader) SetPort(port uint16) {
	copy(this[net.IPv6len*4:], tcp.HtoNs(port))
}

func (this *ConnectionHelloHeader) GetPort() uint16 {
	return tcp.NtoHs(this[net.IPv6len*4:])
}

func (this *ConnectionHelloHeader) SetClusterAddress(ip net.IP) {
	this.setAddress(0, ip)
}

func (this *ConnectionHelloHeader) SetClusterCIDR(cidr *net.IPNet) {
	this.setCIDR(0, cidr)
}

func (this *ConnectionHelloHeader) GetClusterAddress() net.IP {
	return this.getAddress(0)
}

func (this *ConnectionHelloHeader) GetClusterCIDR() *net.IPNet {
	return this.getCIDR(0)
}

func (this *ConnectionHelloHeader) SetCIDR(cidr *net.IPNet) {
	this.setCIDR(net.IPv6len*2, cidr)
}

func (this *ConnectionHelloHeader) GetCIDR() *net.IPNet {
	return this.getCIDR(net.IPv6len * 2)
}

func to16Mask(mask net.IPMask) net.IPMask {
	if len(mask) == net.IPv6len {
		return mask
	}
	if len(mask) == net.IPv4len {
		r := net.CIDRMask((net.IPv6len-net.IPv4len)*8, net.IPv6len)
		copy(r[(net.IPv6len-net.IPv4len)*8:], mask)
		return r
	}
	return nil
}
