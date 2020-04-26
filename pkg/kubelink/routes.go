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

package kubelink

import (
	"fmt"

	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"

	"github.com/mandelsoft/k8sbridge/pkg/tcp"
)

type Routes []netlink.Route

func (this Routes) Lookup(route netlink.Route) int {
	for i, r := range this {
		if r.LinkIndex == route.LinkIndex &&
			r.Gw.Equal(route.Gw) &&
			tcp.EqualCIDR(r.Dst, route.Dst) {
			return i
		}
	}
	return -1
}

func (this Routes) LookupAndLogMismatchReason(logger logger.LogContext, route netlink.Route) int {
	for i, r := range this {
		if r.LinkIndex != route.LinkIndex {
			logger.Infof("index mismatch for %s ( %d!=%d)", r, r.LinkIndex, route.LinkIndex)
			continue
		}
		if !r.Gw.Equal(route.Gw) {
			logger.Infof("gateway mismatch for %s (%s!=%s)", r, r.Gw, route.Gw.String())
			continue
		}
		if !tcp.EqualCIDR(r.Dst, route.Dst) {
			logger.Infof("destination mismatch for %s (%s!=%s)", r, r.Dst, route.Dst)
			continue
		}
		return i
	}
	return -1
}

func (this *Routes) Add(route netlink.Route) Routes {
	if this.Lookup(route) < 0 {
		*this = append(*this, route)
	}
	return *this
}

func ShowRoutes(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("cannot get link %q: %s", name, err)
	}

	fmt.Printf("link index: %d\n", link.Attrs().Index)
	routes, err := netlink.RouteList(link, nl.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("cannot get routes: %s", err)
	}
	for i, r := range routes {
		fmt.Printf("Route %d: %s\n", i, r)
	}
	return nil
}

func ListRoutesForInterface(name string) (Routes, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("cannot get link %q: %s", name, err)
	}

	routes, err := netlink.RouteList(link, nl.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("cannot get routes: %s", err)
	}
	return Routes(routes), nil
}

func ListRoutes() (Routes, error) {
	var routes Routes
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("cannot get link list: %s", err)
	}

	for _, link := range links {
		r, err := netlink.RouteList(link, nl.FAMILY_V4)
		if err != nil {
			return nil, fmt.Errorf("cannot get routes: %s", err)
		}
		routes = append(routes, r...)

	}
	return routes, nil
}
