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
	"os"

	"github.com/gardener/controller-manager-library/pkg/logger"

	"github.com/mandelsoft/kubelink/pkg/controllers"
	"github.com/mandelsoft/kubelink/pkg/iptables"
	"github.com/mandelsoft/kubelink/pkg/kubelink"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

func test() {
}

func CheckErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

func main() {
	test()
	fmt.Println("Hello iptables")

	name := "test"
	if len(os.Args) > 1 {
		name = os.Args[1]
	}
	tool, err := controllers.NewLinkTool()
	CheckErr(err)

	links := kubelink.NewLinks(nil, 8777)

	ingress, err := kubelink.ParseIPRange([]string{"192.168.5.0/28", "!192.168.5.5/32"})
	CheckErr(err)

	cidr, _ := tcp.ParseIPNet("192.168.0.13/24")

	link := &kubelink.Link{
		Name:           name,
		Ingress:        ingress,
		ClusterAddress: cidr,
	}
	links.ReplaceLink(link)

	chains := iptables.Requests{}
	if name != "clear" {
		chains = links.GetFirewallChains()

	}
	logger.SetLevel("debug")
	logger := logger.New()

	err = tool.HandleFirewall(logger, chains)
	CheckErr(err)
	_ = tool
}
