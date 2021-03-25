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

package controllers

import (
	"fmt"
	"net"
	"strings"

	"github.com/gardener/controller-manager-library/pkg/config"

	"github.com/mandelsoft/kubelink/pkg/utils"
)

const IPIP_NONE = "none"
const IPIP_SHARED = "shared"
const IPIP_CONFIGURE = "configure"

const RTTABLE_MAIN = 254
const RTTABLE_PRIO = 32750

type Config struct {
	nodecidr string
	podcidr  string

	PodCIDR  *net.IPNet
	NodeCIDR *net.IPNet
	IPIP     string

	RouteTable uint
	RulePrio   uint
}

var _ config.OptionSource = &Config{}

func (this *Config) AddOptionsToSet(set config.OptionSet) {
	set.AddStringOption(&this.nodecidr, "node-cidr", "", "", "CIDR of node network of cluster")
	set.AddStringOption(&this.podcidr, "pod-cidr", "", "", "CIDR of pod network of cluster")
	set.AddStringOption(&this.IPIP, "ipip", "", IPIP_NONE, "ip-ip tunnel mode (none, shared, configure")

	set.AddUintOption(&this.RouteTable, "route-table", "", RTTABLE_MAIN, "route table to use")
	set.AddUintOption(&this.RulePrio, "rule-priority", "", RTTABLE_PRIO, "rule priority for optional route table rule")
}

func (this *Config) Prepare() error {
	var err error

	_, this.NodeCIDR, err = this.RequireCIDR(this.nodecidr, "node-cidr")
	if err != nil {
		return err
	}

	_, this.PodCIDR, err = this.OptionalCIDR(this.podcidr, "pod-cidr")
	if err != nil {
		return err
	}

	if this.RouteTable > 254 {
		return fmt.Errorf("invalid route table %d", this.RouteTable)
	}
	ipip := strings.TrimSpace(strings.ToLower(this.IPIP))
	switch ipip {
	case IPIP_NONE, IPIP_SHARED, IPIP_CONFIGURE:
		this.IPIP = ipip
	default:
		return fmt.Errorf("invalid ipip mode: %s", this.IPIP)
	}
	return nil
}

func (this *Config) RequireCIDR(s, name string) (net.IP, *net.IPNet, error) {
	return utils.RequireCIDR(s, name)
}

func (this *Config) OptionalCIDR(s, name string) (net.IP, *net.IPNet, error) {
	return utils.OptionalCIDR(s, name)
}
