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
	"net"

	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/vishvananda/netlink"
)

type InterfaceInfo struct {
	Name  string
	Index int
	IP    net.IP
}

func (this *InterfaceInfo) String() string {
	if this == nil {
		return "<NoInterface>"
	}
	return fmt.Sprintf("%s(%d)[%s]", this.Name, this.Index, this.IP)
}

func LookupIPForCIDR(logger logger.LogContext, msg string, cidr *net.IPNet) (*InterfaceInfo, error) {
	var ifce *InterfaceInfo

	if logger != nil {
		logger.Infof("lookup %s ip", msg)
	}
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if cidr.Contains(ip) {
				if logger != nil {
					logger.Infof("  %s: found %s IP %q", i.Name, msg, ip)
				}
				ifce = &InterfaceInfo{
					Name:  i.Name,
					Index: i.Index,
					IP:    ip,
				}
			} else {
				if logger != nil {
					logger.Infof("  %s: found IP %q", i.Name, ip)
				}
			}
		}
	}
	if ifce != nil {
		if logger != nil {
			logger.Infof("using %s ip %q (on interface %s[%d])", msg, ifce.IP, ifce.Name, ifce.Index)
		}
	}
	return ifce, nil
}

func LookupPodInterface(logger logger.LogContext, qip net.IP) (*InterfaceInfo, error) {
	var ifce *InterfaceInfo

	routes, err := ListRoutes(MAIN_TABLE)
	if err != nil {
		return nil, err
	}
	for _, r := range routes {
		if r.Dst != nil && qip.Equal(r.Dst.IP) {
			link, err := netlink.LinkByIndex(r.LinkIndex)
			if err == nil {
				if logger != nil {
					logger.Infof("found pod interface %q for %s", link.Attrs().Name, qip)
				}
				ifce = &InterfaceInfo{
					Name:  link.Attrs().Name,
					Index: r.LinkIndex,
					IP:    qip,
				}
				return ifce, nil
			}
			logger.Infof("cannot get link for index %d: %s", r.LinkIndex, err)
		}
	}

	return nil, fmt.Errorf("no valid pod interface found for %s", qip)
}
