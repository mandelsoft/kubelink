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
	"strconv"

	"github.com/vishvananda/netlink"
)

func listRules() {
	rules, err := netlink.RuleList(netlink.FAMILY_ALL)
	if err != nil {
		Error("cannot list rules: %s", err)
	}
	for _, r := range rules {
		fmt.Printf("%#v\n", r)
	}
}

func addRule(args []string) {
	if len(args) != 2 {
		Error("pro and table required")
	}
	prio, err := strconv.ParseInt(args[0], 10, 32)
	if err != nil {
		Error("invalid prio: %s", err)
	}
	table, err := strconv.ParseInt(args[1], 10, 32)
	if err != nil {
		Error("invalid table: %s", err)
	}

	r := netlink.NewRule()
	r.Priority = int(prio)
	r.Table = int(table)
	err = netlink.RuleAdd(r)
	if err != nil {
		Error("cannot add rule: %s", err)
	}
}
