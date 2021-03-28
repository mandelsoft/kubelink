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

package main

import (
	"net"

	"github.com/vishvananda/netlink"
)

func addRoute(args []string) {

	if len(args) != 2 {
		Error("dst and gw required")
	}
	_, dst, err := net.ParseCIDR(args[0])
	if err != nil {
		Error("invalid destination: %s", err)
	}
	gw := net.ParseIP(args[1])
	if gw == nil {
		Error("invalid gateway")
	}
	r := &netlink.Route{
		LinkIndex: 0,
		Dst:       dst,
		Gw:        gw,
	}
	err = netlink.RouteAdd(r)
	if err != nil {
		Error("cannot add route %s: %s", r, err)
	}
}
