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
	"net"

	"github.com/gardener/controller-manager-library/pkg/utils"

	"github.com/mandelsoft/kubelink/pkg/iptables"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

const TABLE_NAT = "nat"
const NAT_CHAIN = CHAIN_PREFIX + "NAT"
const NAT_MESH_CHAIN_PREFIX = CHAIN_PREFIX + "NT-"

func NatEmbedding(linkName string) ([]RuleDef, utils.StringSet) {
	// touched tables
	tables := utils.NewStringSet(TABLE_NAT)
	return []RuleDef{
		RuleDef{TABLE_NAT, "POSTROUTING", iptables.Rule{
			iptables.Opt("-m", "comment", "--comment", "kubelink nat rules"),
			iptables.Opt("-o", linkName),
			iptables.Opt("-j", NAT_CHAIN),
		}, ""},
	}, tables
}

func (this *Links) GetGatewayAddrs() tcp.CIDRList {
	meshes := this.GetMeshLinks()
	addrs := tcp.CIDRList{}
	for _, m := range meshes {
		addrs.Add(m.ClusterAddress)
	}
	return addrs
}

func (this *Links) GetNatChains(clusterAddresses tcp.CIDRList) iptables.Requests {
	this.lock.RLock()
	defer this.lock.RUnlock()

	var natchains iptables.Requests
	var rules iptables.Rules
	meshes := map[string]*iptables.ChainRequest{}

	this.links.Visit(func(l *Link) bool {
		var clusterAddress *net.IPNet

		mesh := tcp.CIDRNet(l.ClusterAddress)
		for _, cidr := range clusterAddresses {
			if mesh.Contains(cidr.IP) {
				clusterAddress = cidr
				return false
			}
		}
		if clusterAddress == nil {
			return true
		}
		chain := meshes[mesh.String()]
		if chain == nil {

			natRules := iptables.Rules{
				iptables.Rule{
					iptables.Opt("-m", "comment", "--comment", "nat for mesh "+mesh.String()),
				},
			}
			if len(clusterAddresses) == 1 { // simplified ruleset
				natRules = append(natRules,
					iptables.Rule{
						iptables.ComposeOpt("-j", "SNAT", iptables.Opt("--to-source", clusterAddress.IP.String())),
					},
				)
			} else {
				natRules = append(natRules,
					iptables.Rule{
						iptables.Opt("-s", mesh.String()),
						iptables.Opt("-j", "ACCEPT"),
					},
				)
			}
			chain = iptables.NewChainRequest(
				TABLE_NAT,
				NAT_MESH_CHAIN_PREFIX+encodeName(mesh.String()),
				natRules, true)

			natchains = append(natchains, chain)
			meshes[mesh.String()] = chain
			rules = append(rules, iptables.Rule{
				iptables.Opt("-j", chain.Chain.Chain),
			})
		}
		// append link rules
		if len(clusterAddresses) > 1 { // multi mesh scenario with dedicated SNATs
			for _, e := range l.Egress {
				chain.Rules = append(chain.Rules,
					iptables.Rule{
						iptables.Opt("-m", "comment", "--comment", "link "+l.Name.String()),
						iptables.Opt("-d", e.String()),
						iptables.ComposeOpt("-j", "SNAT", iptables.Opt("--to-source", clusterAddress.IP.String())),
					},
				)
			}
		}
		return true
	})

	var chains iptables.Requests
	if len(rules) > 0 {
		chains = append(chains, natchains...)
		chains = append(chains, iptables.NewChainRequest(
			TABLE_NAT,
			NAT_CHAIN,
			rules, true,
		))
	}

	return chains
}
