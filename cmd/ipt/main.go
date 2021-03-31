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

	"github.com/gardener/controller-manager-library/pkg/logger"

	"github.com/mandelsoft/kubelink/pkg/controllers"
	"github.com/mandelsoft/kubelink/pkg/iptables"
	"github.com/mandelsoft/kubelink/pkg/kubelink"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

func CheckErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

func main() {
	nat := false
	clear := false
	args := []string{}

	for _, arg := range os.Args[1:] {
		switch arg {
		case "-nat":
			nat = true
		case "-fw":
			nat = false
		case "-clear", "clear":
			clear = true
		default:
			args = append(args, arg)
		}
	}
	if clear {
		fmt.Print("Clearing ")
	} else {
		fmt.Print("Configuring ")
	}
	if nat {
		fmt.Println("NAT")
	} else {
		fmt.Println("Firewall")
	}

	name := "test"
	if len(args) > 0 {
		name = args[0]
	}
	lname := kubelink.NewLinkName("mesh", name)
	tool, err := controllers.NewLinkTool()
	CheckErr(err)

	links := kubelink.NewLinks(nil, 8777)

	ingress, err := kubelink.ParseFirewallRule([]string{"192.168.5.0/28", "!192.168.5.5/32"})
	CheckErr(err)

	addr, _ := tcp.ParseIPNet("192.168.0.1/24")
	cidr, _ := tcp.ParseIPNet("192.168.0.13/24")
	egress, _ := tcp.ParseIPNet("100.64.16.0/22")

	fw, err := kubelink.ParseFirewallRule([]string{"100.64.0.0/16"})
	CheckErr(err)

	link := &kubelink.Link{
		Name:           lname,
		Ingress:        ingress,
		ClusterAddress: cidr,
		Egress:         []*net.IPNet{egress},
	}
	links.ReplaceLink(link)

	mname := kubelink.NewLinkName("mesh", "local")
	mlink := &kubelink.Link{
		Name:           mname,
		Endpoint:       kubelink.EP_LOCAL,
		ClusterAddress: addr,
		Ingress:        fw,
	}
	links.ReplaceLink(mlink)

	fwChains := iptables.Requests{}
	natChains := iptables.Requests{}
	if !clear {
		fwChains = links.GetFirewallChains()
		natChains = links.GetNatChains(nil, tcp.CIDRList{addr}, "kubelink")
	}

	logger.SetLevel("debug")
	logger := logger.New()

	if nat {
		err = tool.HandleNat(logger, natChains)
	} else {
		err = tool.HandleFirewall(logger, fwChains)
	}
	CheckErr(err)
}
