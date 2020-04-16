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
)

type Config struct {
	nodecidr string

	NodeCIDR *net.IPNet
}

var _ config.OptionSource = &Config{}

func (this *Config) AddOptionsToSet(set config.OptionSet) {
	set.AddStringOption(&this.nodecidr, "node-cidr", "", "", "CIDR of node network of cluster")
}

func (this *Config) Prepare() error {
	var err error

	_, this.NodeCIDR, err = this.RequireCIDR(this.nodecidr, "node-cidr")
	if err != nil {
		return err
	}
	return nil
}

func (this *Config) RequireCIDR(s, name string) (net.IP, *net.IPNet, error) {
	ip, cidr, err := this.OptionalCIDR(s, name)
	if cidr == nil && err == nil {
		return nil, nil, fmt.Errorf("%s must be set", name)
	}
	return ip, cidr, nil
}

func (this *Config) OptionalCIDR(s, name string) (net.IP, *net.IPNet, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil, nil
	}
	ip, cidr, err := net.ParseCIDR(s)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid cidr (%s): %s", name, err)
	}
	return ip, cidr, nil
}
