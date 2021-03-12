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

package kubelink

import (
	"fmt"
	"net"

	"github.com/mandelsoft/kubelink/pkg/tcp"
)

type FirewallRule struct {
	Allowed tcp.CIDRList
	Denied  tcp.CIDRList
}

func ParseFirewallRule(list []string) (*FirewallRule, error) {
	var r *FirewallRule
	if len(list) > 0 {
		r = &FirewallRule{}
		for _, c := range list {
			field := &r.Allowed
			if len(c) > 0 {
				if c[0] == '!' {
					field = &r.Denied
					c = c[1:]
				}
			}
			cidr, err := tcp.ParseNet(c)
			if err != nil {
				return nil, fmt.Errorf("invalid cidr %q: %s", c, err)
			}
			field.Add(cidr)
		}
	}
	return r, nil
}

func (this *FirewallRule) IsSet() bool {
	return this != nil && (this.Allowed.IsSet() || this.Denied.IsSet())
}

func (this *FirewallRule) Contains(ip net.IP) bool {
	if this == nil {
		return true
	}
	if !this.Allowed.IsSet() || this.Allowed.Contains(ip) {
		for _, c := range this.Denied {
			if c.Contains(ip) {
				return false
			}
		}
	}
	return true
}
