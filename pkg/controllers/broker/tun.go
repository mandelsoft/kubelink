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

	"github.com/coreos/go-iptables/iptables"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/vishvananda/netlink"

	"github.com/mandelsoft/k8sbridge/pkg/taptun"
)

const IPTAB = "nat"
const IPCHAIN = "POSTROUTING"

type Tun struct {
	tun       *taptun.Tun
	link      netlink.Link
	finalizer func()
}

func (this *Tun) String() string {
	return fmt.Sprintf("%s[%d]", this.tun.String(), this.link.Attrs().Index)
}

func (this *Tun) Close() error {
	if this.finalizer != nil {
		this.finalizer()
	}
	return this.tun.Close()
}

func (this *Tun) Write(data []byte) (int, error) {
	return this.tun.Write(data)
}

func (this *Tun) Read(buf []byte) (int, error) {
	return this.tun.Read(buf)
}

////////////////////////////////////////////////////////////////////////////////

func NewTun(logger logger.LogContext, clusterAddress net.IP, clusterCIDR *net.IPNet) (*Tun, error) {

	tun, err := taptun.NewTun("")
	if err != nil {
		return nil, fmt.Errorf("cannot create tun %q: %s", tun, err)
	}
	logger.Infof("created tun device %q", tun)

	ipt, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("cannot create iptables access: %s", err)
	}

	link, err := netlink.LinkByName(tun.String())
	if err != nil {
		tun.Close()
		return nil, fmt.Errorf("cannot get link for %q: %s", tun, err)
	}

	rule := []string{"-o", tun.String(), "-j", "SNAT", "--to-source", clusterAddress.String()}
	ok, err := ipt.Exists(IPTAB, IPCHAIN, rule...)
	if err != nil {
		tun.Close()
		return nil, fmt.Errorf("cannot check nat: %s", err)
	}

	if ok {
		logger.Infof("nat rule %v already exists", rule)
	} else {
		err = ipt.Append(IPTAB, IPCHAIN, rule...)
		if err != nil {
			tun.Close()
			return nil, fmt.Errorf("cannot add nat rule %v: %s", rule, err)
		}
		logger.Infof("added nat rule %v", rule)
	}
	result := &Tun{
		tun,
		link,
		func() {
			ipt.Delete(IPTAB, IPCHAIN, rule...)
			tun.Close()
		},
	}

	cidr := *clusterCIDR
	cidr.IP = clusterAddress

	addr := &netlink.Addr{
		IPNet: &cidr,
	}
	logger.Infof("adding address %s to %q", cidr.String(), tun)
	err = netlink.AddrAdd(link, addr)
	if err != nil {
		result.Close()
		return nil, fmt.Errorf("cannot add addr %q to %s: %s", addr, tun, err)
	}

	err = netlink.LinkSetUp(link)
	if err != nil {
		result.Close()
		return nil, fmt.Errorf("cannot bring up %q: %s", tun, err)
	}

	ifce, err := net.InterfaceByName(tun.String())
	if err != nil {
		result.Close()
		return nil, fmt.Errorf("cannot get tun %q: %s", tun, err)
	}

	addrs, err := ifce.Addrs()
	if err != nil {
		result.Close()
		return nil, fmt.Errorf("cannot get addresses for %s: %s", tun, err)
	}
	logger.Infof("%s: MTU: %d, Flags: %s, Addr: %v", result, ifce.MTU, ifce.Flags, addrs)
	return result, nil
}
