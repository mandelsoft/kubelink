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
)

type NodeInterface struct {
	Name  string
	Index int
	IP    net.IP
}

func LookupNodeIP(logger logger.LogContext, cidr *net.IPNet) (*NodeInterface, error) {
	var ifce *NodeInterface

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
					logger.Infof("%s: found node IP %q", i.Name, ip)
				}
				ifce = &NodeInterface{
					Name:  i.Name,
					Index: i.Index,
					IP:    ip,
				}
			} else {
				if logger != nil {
					logger.Infof("%s: found IP %q", i.Name, ip)
				}
			}
		}
	}

	if ifce == nil {
		return nil, fmt.Errorf("no valid node ip found for cidr %s on any interface", cidr)
	}
	if logger != nil {
		logger.Infof("using node ip %q (on interface %s[%d])", ifce.IP, ifce.Name, ifce.Index)
	}
	return ifce, nil
}
