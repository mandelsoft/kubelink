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

package main

import (
	"fmt"
	"net"
	"time"

	"github.com/gardener/controller-manager-library/pkg/utils"

	"github.com/mandelsoft/kubelink/pkg/iptables"
	"github.com/mandelsoft/kubelink/pkg/kubelink"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

func main() {
	var list tcp.CIDRList

	fmt.Printf("set: %t, empty: %t\n", list.IsSet(), list.IsEmpty())

	list = tcp.CIDRList{}
	fmt.Printf("set: %t, empty: %t\n", list.IsSet(), list.IsEmpty())
	list.Add(&net.IPNet{})
	fmt.Printf("set: %t, empty: %t\n", list.IsSet(), list.IsEmpty())

	access := kubelink.LinkAccessInfo{
		CACert: "CERT",
		Token:  "TOKEN",
	}
	fmt.Printf("direct : %s\n", access)
	fmt.Printf("pointer: %s\n", &access)

	r := utils.NewDefaultRateLimiter(10*time.Second, 10*time.Minute)

	for i := 1; i < 20; i++ {
		r.Failed()
		fmt.Printf("%d: %s\n", i, r.RateLimit())
	}

	args := []string{
		"-A", "chain", "-o", "eth0", "-d", "127.2.2.2", "-j", "SNAT", "--to-source", "x",
	}

	rule := iptables.ParseRule(args)
	fmt.Printf("rule: %+v\n", rule)
	fmt.Printf("list: %+v\n", rule.AsList())
	rule.Remove(iptables.Opt("-j", "SNAT"))
	fmt.Printf("rem: %+v\n", rule.RemoveOption("-A"))
}
