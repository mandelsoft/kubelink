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
	"os"

	"github.com/mandelsoft/kubelink/pkg/controllers/router"
	"github.com/mandelsoft/kubelink/pkg/kubelink"
)

func main() {
	_, cidr, _ := net.ParseCIDR("192.168.0.11/24")
	meshName := kubelink.NewLinkName("test", "link0")
	mesh := &kubelink.Link{
		Name:            meshName,
		ServiceCIDR:     nil,
		Egress:          nil,
		Ingress:         nil,
		ClusterAddress:  cidr,
		GatewayLink:     nil,
		GatewayFor:      nil,
		Gateway:         nil,
		Host:            "",
		Port:            0,
		Endpoint:        kubelink.EP_LOCAL,
		PublicKey:       nil,
		PresharedKey:    nil,
		LinkForeignData: kubelink.LinkForeignData{LinkDNSInfo: kubelink.LinkDNSInfo{DNSPropagation: false}},
	}

	links := kubelink.NewLinks(nil, 0)

	links.ReplaceLink(mesh)

	fmt.Printf("mesh %v\n", links.GetMesh("test"))
	links.RemoveLink(meshName)
	fmt.Printf("mesh %v\n", links.GetMesh("test"))

	_, err := router.ReadRoutes("test")
	if os.IsNotExist(err) {
		fmt.Printf("not found")
	}
}
