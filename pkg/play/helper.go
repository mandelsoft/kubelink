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

package play

import (
	"fmt"
	"io"
	"log"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/mandelsoft/kubelink/pkg"
)

const ROUTE = "192.168.3.0/24"
const TUNIP = "192.168.1.2"
const TUNCIDR = TUNIP + "/24"

func ConfigureTun(name string) {
	link, err := netlink.LinkByName(name)
	pkg.ExitOnErr("cannot get link %q", name, err)

	addr, err := netlink.ParseAddr(TUNCIDR)
	pkg.ExitOnErr("cannot create addr %q", TUNCIDR, err)

	err = netlink.AddrAdd(link, addr)
	pkg.ExitOnErr("cannot add addr %q", TUNCIDR, err)

	err = netlink.LinkSetUp(link)
	pkg.ExitOnErr("cannot bring up %q", name, err)

	_, dst, err := net.ParseCIDR(ROUTE)
	pkg.ExitOnErr("cannot parse cidr %q", ROUTE, err)
	route := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst}
	err = netlink.RouteAdd(route)
	pkg.ExitOnErr("cannot add route", err)
}

func TraceTun(fd io.Reader) {
	buffer := [2000]byte{}
	for {
		n, err := fd.Read(buffer[:])
		if n <= 0 || err != nil {
			fmt.Printf("END: %d bytes, err=%s\n", n, err)
			break
		}
		log.Printf("Read %d bytes", n)
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
