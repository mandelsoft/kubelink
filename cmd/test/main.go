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
	"fmt"
	"net"

	"github.com/vishvananda/netlink"

	"github.com/mandelsoft/kubelink/pkg/kubelink"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

func main() {
	addr, _ := netlink.ParseIPNet("192.168.100.1/24")

	svc0 := &kubelink.Service{
		Key: "service0",
		Ports: []kubelink.ServicePort{
			{
				Protocol: "",
				Port:     80,
			},
		},
		Endpoints: kubelink.ServiceEndpoints{
			{
				Address: net.ParseIP("100.64.0.30"),
				PortMappings: []kubelink.PortMapping{
					{
						Port: kubelink.ServicePort{
							Port: 80,
						},
						TargetPort: 8080,
					},
				},
			},
		},
	}

	svc1 := &kubelink.Service{
		Key:     "service1",
		Address: net.ParseIP("192.168.100.21"),
		Ports:   nil,
		Endpoints: kubelink.ServiceEndpoints{
			{
				Address:      net.ParseIP("100.64.0.60"),
				PortMappings: nil,
			},
			{
				Address:      net.ParseIP("100.64.0.50"),
				PortMappings: nil,
			},
		},
	}

	svc2 := &kubelink.Service{
		Key:     "service2",
		Address: net.ParseIP("192.168.100.22"),
		Ports: []kubelink.ServicePort{
			{
				Protocol: "",
				Port:     80,
			},
			{
				Protocol: "",
				Port:     443,
			},
		},
		Endpoints: kubelink.ServiceEndpoints{
			{
				Address:      net.ParseIP("100.64.0.50"),
				PortMappings: nil,
			},
			{
				Address: net.ParseIP("100.64.0.60"),
				PortMappings: []kubelink.PortMapping{
					{
						Port: kubelink.ServicePort{
							Port: 443,
						},
						TargetPort: 8443,
					},
				},
			},
		},
	}

	links := kubelink.NewLinks(nil, 0)
	links.SetDefaultMesh("linkdef", addr, kubelink.LinkDNSInfo{})
	links.UpdateService(svc0)
	links.UpdateService(svc1)
	links.UpdateService(svc2)

	req := links.GetServiceChains(nil, tcp.CIDRList{addr})
	fmt.Printf("%s\n", req)

	other := &kubelink.Service{
		Key: "service0",
		Ports: []kubelink.ServicePort{
			{
				Protocol: "",
				Port:     80,
			},
		},
		Endpoints: kubelink.ServiceEndpoints{
			{
				Address: net.ParseIP("100.64.0.30"),
				PortMappings: []kubelink.PortMapping{
					{
						Port: kubelink.ServicePort{
							Port: 80,
						},
						TargetPort: 8080,
					},
				},
			},
		},
	}

	other.Normalize()

	fmt.Printf("equal: %t\n", other.Equal(svc0))
}
