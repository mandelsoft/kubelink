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

package tcp

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"

	"github.com/vishvananda/netlink"
)

// onceCloseListener wraps a net.Listener, protecting it from
// multiple Close calls.
type onceCloseListener struct {
	net.Listener
	once     sync.Once
	closeErr error
}

func (oc *onceCloseListener) Close() error {
	oc.once.Do(oc.close)
	return oc.closeErr
}

func (oc *onceCloseListener) close() { oc.closeErr = oc.Listener.Close() }

// cloneTLSConfig returns a shallow clone of cfg, or a new zero tls.Config if
// cfg is nil. This is safe to call even if cfg is in active use by a TLS
// client or server.
func cloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return cfg.Clone()
}

func EqualIP(a, b net.IP) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Equal(b)
}

func CloneIP(ip net.IP) net.IP {
	return append(ip[:0:0], ip...)
}

func SubIP(cidr *net.IPNet, n int) net.IP {
	ip := CloneIP(cidr.IP)

	i := len(ip) - 1
	for n > 0 {
		n += int(ip[i])
		ip[i] = uint8(n % 256)
		n = n / 256
		i--
	}
	return ip
}

func ContainsCIDR(a, b *net.IPNet) bool {
	if !a.Contains(b.IP) {
		return false
	}
	a_ones, a_bits := b.Mask.Size()
	b_ones, b_bits := b.Mask.Size()
	return b_bits-b_ones <= a_bits-a_ones

}

func EqualCIDR(a, b *net.IPNet) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if !a.IP.Equal(b.IP) {
		return false
	}
	if !net.IP(a.Mask).Equal(net.IP(b.Mask)) {
		return false
	}
	return true
}

func CIDRNet(cidr *net.IPNet) *net.IPNet {
	if cidr == nil {
		return nil
	}
	net := *cidr
	net.IP = cidr.IP.Mask(cidr.Mask)
	return &net
}

func CIDRIP(cidr *net.IPNet, ip net.IP) *net.IPNet {
	if cidr == nil || len(ip) == 0 {
		return nil
	}
	if len(cidr.IP) != len(ip) {
		if len(cidr.IP) == net.IPv6len {
			ip = ip.To16()
		} else {
			ip = ip.To4()
			if ip == nil {
				panic("incompatible ip and cidr")
			}
		}
	}
	if !cidr.Contains(ip) {
		panic(fmt.Sprintf("cidr %s does not contain ip %s", cidr, ip))
	}
	net := *cidr
	net.IP = ip
	return &net
}

func IPtoCIDR(ip net.IP) *net.IPNet {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return &net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(len(ip)*8, len(ip)*8),
	}
}

// ParseIPNet parses a cidr and return
// the specified ip/netmask as single IPNet
func ParseIPNet(s string) (*net.IPNet, error) {
	ip, cidr, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	return CIDRIP(cidr, ip), nil
}

// ParseIPCIDR parses an ip or cidr and returns
// the specified ip/netmask as single IPNet
func ParseIPCIDR(s string) (*net.IPNet, error) {
	ip, cidr, err := net.ParseCIDR(s)
	if err == nil {
		return CIDRIP(cidr, ip), nil
	}
	ip = net.ParseIP(s)
	if ip == nil {
		return nil, err
	}
	return IPtoCIDR(ip), nil
}

// ParseNet parses an ip or cidr and returns
// the result as cidr describing the netmask/network, only
func ParseNet(s string) (*net.IPNet, error) {
	ip, cidr, err := net.ParseCIDR(s)
	if err == nil {
		return cidr, nil
	}
	ip = net.ParseIP(s)
	if ip == nil {
		return nil, err
	}
	return IPtoCIDR(ip), nil
}

////////////////////////////////////////////////////////////////////////////////

type CIDRList []*net.IPNet

func (this CIDRList) Equivalent(other CIDRList) bool {
	if len(this) != len(other) {
		return false
	}
	for _, e := range this {
		if !other.Has(e) {
			return false
		}
	}
	return true
}

func (this *CIDRList) String() string {
	sep := "["
	end := ""
	s := ""
	for _, c := range *this {
		s = fmt.Sprintf("%s%s%s", s, sep, c)
		sep = ","
		end = "]"
	}
	return s + end
}

func (this *CIDRList) Add(cidrs ...*net.IPNet) {
	for _, a := range cidrs {
		if this.Has(a) {
			continue
		}
		*this = append(*this, a)
	}
}

func (this *CIDRList) Enrich(cidrs ...*net.IPNet) {
outer:
	for _, a := range cidrs {
		for i := 0; i < len(*this); i++ {
			e := (*this)[i]
			if ContainsCIDR(e, a) {
				continue outer
			}
			if ContainsCIDR(a, e) {
				*this = append((*this)[:i], (*this)[i+1:]...)
				i--
			}
		}
		*this = append(*this, a)
	}
}

func (this *CIDRList) IsEmpty() bool {
	return len(*this) == 0
}

func (this *CIDRList) IsSet() bool {
	return *this != nil
}

func (this *CIDRList) Has(cidr *net.IPNet) bool {
	for _, c := range *this {
		if EqualCIDR(c, cidr) {
			return true
		}
	}
	return false
}

func (this *CIDRList) Contains(ip net.IP) bool {
	for _, c := range *this {
		if c.Contains(ip) {
			return true
		}
	}
	return false
}

func (this *CIDRList) ContainsCIDR(cidr *net.IPNet) bool {
	for _, c := range *this {
		if ContainsCIDR(c, cidr) {
			return true
		}
	}
	return false
}

func (this *CIDRList) Lookup(ip net.IP) *net.IPNet {
	for _, c := range *this {
		if c.Contains(ip) {
			return c
		}
	}
	return nil
}

////////////////////////////////////////////////////////////////////////////////

type IPList []net.IP

func (this IPList) String() string {
	sep := "["
	end := ""
	s := ""
	for _, c := range this {
		s = fmt.Sprintf("%s%s%s", s, sep, c)
		sep = ","
		end = "]"
	}
	return s + end
}

func (this *IPList) Add(ips ...net.IP) {
	*this = append(*this, ips...)
}

func (this IPList) IsEmpty() bool {
	return len(this) == 0
}

func (this IPList) IsSet() bool {
	return this != nil
}

func (this IPList) Contains(ip net.IP) bool {
	for _, c := range this {
		if c.Equal(ip) {
			return true
		}
	}
	return false
}

////////////////////////////////////////////////////////////////////////////////

func Family(ip net.IP) int {
	if ip.To4() == nil {
		return netlink.FAMILY_V6
	}
	return netlink.FAMILY_V4
}
