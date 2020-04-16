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

package pkg

import (
	"fmt"
	"net"

	"github.com/pkg/taptun"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	// "k8s.io/kubernetes/pkg/util/iptables"
	"github.com/coreos/go-iptables/iptables"
)

const ROUTE = "192.168.3.0/24"
const TUNIP = "192.168.1.1"
const TUNCIDR = TUNIP + "/24"
const IPTAB = "nat"
const IPCHAIN = "POSTROUTING"

func RunTun() {
	ipt, err := iptables.New()
	ExitOnErr("cannot create iptables access", err)

	tun, err := taptun.NewTun("")
	ExitOnErr("cannot create tun %q", tun, err)
	fmt.Printf("created %q\n", tun)
	defer tun.Close()

	rule := []string{"-o", tun.String(), "-j", "SNAT", "--to-source", TUNIP}
	ok, err := ipt.Exists(IPTAB, IPCHAIN, rule...)
	ExitOnErr("cannot check nat", err)
	if ok {
		fmt.Printf("nat rule %v already exists\n", rule)
	} else {
		//err = ipt.Append(IPTAB, IPCHAIN, rule...)
		ExitOnErr("cannot add nat rule %v", rule, err)
		fmt.Printf("added nat rule %v\n", rule)
	}
	defer func() {
		ipt.Delete(IPTAB, IPCHAIN, rule...)
	}()

	link, err := netlink.LinkByName(tun.String())
	ExitOnErr("cannot get link %q", tun, err)

	addr, err := netlink.ParseAddr(TUNCIDR)
	ExitOnErr("cannot create addr %q", TUNCIDR, err)

	err = netlink.AddrAdd(link, addr)
	ExitOnErr("cannot add addr %q", TUNCIDR, err)

	err = netlink.LinkSetUp(link)
	ExitOnErr("cannot bring up %q", tun, err)

	_, dst, err := net.ParseCIDR(ROUTE)
	ExitOnErr("cannot parse cidr %q", ROUTE, err)
	route := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst}
	err = netlink.RouteAdd(route)
	ExitOnErr("cannot add route", err)

	ifce, err := net.InterfaceByName(tun.String())
	ExitOnErr("cannot get tun %q", tun, err)

	addrs, err := ifce.Addrs()
	ExitOnErr("cannot get addresses", err)

	fmt.Printf("MTU: %d, Flags: %s, Addr: %v\n", ifce.MTU, ifce.Flags, addrs)

	ShowRoutes(tun.String())

	var buffer [12000]byte

	bytes := buffer[:]
	for {
		n, err := tun.Read(bytes)
		if n <= 0 || err != nil {
			fmt.Printf("END: %d bytes, err=%s\n", n, err)
			break
		}
		vers := int(buffer[0]) >> 4
		if vers == ipv6.Version {
			header, err := ipv6.ParseHeader(buffer[:n])
			if err != nil {
				fmt.Printf("err: %s\n", err)
			} else {

				fmt.Printf("ipv6[%d]: (%d) hdr: %d, payload: %d, prot: %d,  %s->%s\n", header.Version, n, 40, header.PayloadLen, header.NextHeader, header.Src, header.Dst)
			}

		} else {
			header, err := ipv4.ParseHeader(buffer[:n])
			if err != nil {
				fmt.Printf("err: %s\n", err)
			} else {

				fmt.Printf("ipv4[%d]: (%d) hdr: %d, total: %d, prot: %d,  %s->%s\n", header.Version, n, header.Len, header.TotalLen, header.Protocol, header.Src, header.Dst)
			}
		}
	}
}
