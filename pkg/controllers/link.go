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

package controllers

import (
	"fmt"
	"net"

	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/vishvananda/netlink"

	"github.com/mandelsoft/kubelink/pkg/iptables"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

const IPTAB = "nat"
const IPCHAIN = "POSTROUTING"

type LinkTool struct {
	ipt *iptables.IPTables
}

func NewLinkTool() (*LinkTool, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("cannot create iptables access: %s", err)
	}
	return &LinkTool{
		ipt: ipt,
	}, nil
}

func (this *LinkTool) ChainRequest(logger logger.LogContext, req *iptables.ChainRequest) error {
	return this.ipt.Execute(logger, req)
}

func (this *LinkTool) NatRulesExists(rule ...string) (bool, error) {
	return this.ipt.Exists(IPTAB, IPCHAIN, rule...)
}

func (this *LinkTool) NatRulesAppend(rule ...string) error {
	return this.ipt.Append(IPTAB, IPCHAIN, rule...)
}

func (this *LinkTool) NatRulesDelete(rule ...string) error {
	return this.ipt.Append(IPTAB, IPCHAIN, rule...)
}

func (this *LinkTool) PrepareLink(link netlink.Link, clusterAddress *net.IPNet) error {
	name := link.Attrs().Name

	err := this.SetLinkAddress(link, clusterAddress)
	if err != nil {
		return err
	}

	rule := []string{"-o", name, "-j", "SNAT", "--to-source", clusterAddress.IP.String()}
	ok, err := this.ipt.Exists(IPTAB, IPCHAIN, rule...)
	if err != nil {
		return fmt.Errorf("cannot check nat: %s", err)
	}

	if !ok {
		err = this.ipt.Append(IPTAB, IPCHAIN, rule...)
		if err != nil {
			return fmt.Errorf("cannot add nat rule %v: %s", rule, err)
		}
		logger.Infof("added nat rule %v", rule)
	}
	return nil
}

func (this *LinkTool) SetLinkAddress(link netlink.Link, addr *net.IPNet) error {
	nladdr := &netlink.Addr{
		IPNet: addr,
	}

	addrs, _ := netlink.AddrList(link, netlink.FAMILY_V4)
	found := false
	for _, a := range addrs {
		if tcp.EqualCIDR(a.IPNet, addr) {
			found = true
		} else {
			if a.IP.Equal(addr.IP) {
				err := netlink.AddrDel(link, &a)
				if err != nil {
					logger.Errorf("cannot remove old link address %q", a.IPNet)
				}
			}
		}
	}

	if !found {
		err := netlink.AddrReplace(link, nladdr)
		if err != nil {
			return fmt.Errorf("cannot add addr %q to %s: %s", addr, link.Attrs().Name, err)
		}
	}

	err := netlink.LinkSetUp(link)
	if err != nil {
		return fmt.Errorf("cannot bring up %q: %s", link.Attrs().Name, err)
	}
	return nil
}
