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

func SNatEmbedding() ([]RuleDef, utils.StringSet) {
	// touched tables
	tables := utils.NewStringSet(TABLE_NAT)
	return []RuleDef{
		RuleDef{TABLE_NAT, "POSTROUTING",
			iptables.Rule{
				iptables.R_CommentOpt("kubelink snat rules"),
				iptables.R_JumpChainOpt(NAT_CHAIN),
			}, nil,
		},
	}, tables
}

func (this *linksdata) GetGatewayAddrs() tcp.CIDRList {
	meshes := this.GetMeshLinks()
	addrs := tcp.CIDRList{}
	for _, m := range meshes {
		addrs.Add(m.ClusterAddress)
	}
	return addrs
}

func (this *links) GetSNatChains(clusterAddresses tcp.CIDRList, linkName string) iptables.Requests {
	type meshNAT struct {
		chain          *iptables.ChainRequest
		egress         tcp.CIDRList
		clusterAddress *net.IPNet
	}

	var natchains iptables.Requests
	var rules iptables.Rules
	meshes := map[string]*meshNAT{}

	// fmt.Printf("lookup nat chains for: %s", clusterAddresses)
	this.links.Visit(func(l *Link) bool {
		var clusterAddress *net.IPNet

		mesh := tcp.CIDRNet(l.ClusterAddress)
		for _, cidr := range clusterAddresses {
			if mesh.Contains(cidr.IP) {
				clusterAddress = cidr
				break
			}
		}
		if clusterAddress == nil {
			return true
		}
		nat := meshes[mesh.String()]
		if nat == nil {
			natRules := iptables.Rules{
				iptables.Rule{
					iptables.R_CommentOpt("nat for mesh " + mesh.String()),
				},
			}
			if len(clusterAddresses) == 1 { // simplified ruleset
				natRules = append(natRules,
					iptables.Rule{
						iptables.R_SNATOpt(clusterAddress.IP.String()),
					},
				)
			} else {
				natRules = append(natRules,
					iptables.Rule{
						iptables.R_SourceOpt(mesh.String()),
						iptables.R_AcceptOpt(),
					},
				)
			}
			nat = &meshNAT{
				chain: iptables.NewChainRequest(
					TABLE_NAT,
					NAT_MESH_CHAIN_PREFIX+encodeName(mesh.String()),
					natRules, true),
				egress:         tcp.CIDRList{mesh},
				clusterAddress: clusterAddress,
			}

			natchains = append(natchains, nat.chain)
			meshes[mesh.String()] = nat
			rules = append(rules, iptables.Rule{
				iptables.R_JumpChainOpt(nat.chain.Chain.Chain),
			})
		}
		// append link rules
		if len(clusterAddresses) > 1 { // multi mesh scenario with dedicated SNATs
			for _, e := range l.Egress {
				nat.egress.Enrich(e)
			}
		}
		return true
	})

	var chains iptables.Requests

	for _, nat := range meshes {
		// TODO switch to IPsets
		for _, e := range nat.egress {
			nat.chain.Rules = append(nat.chain.Rules,
				iptables.Rule{
					iptables.R_DestOpt(e.String()),
					iptables.R_SNATOpt(nat.clusterAddress.IP.String()),
				},
			)
		}
	}
	rules = append(append(rules[:0:0], iptables.Rule{
		iptables.R_Not(iptables.R_OutOpt(linkName)),
		iptables.R_ReturnOpt(),
	}), rules...)
	chains = append(chains, natchains...)
	chains = append(chains, iptables.NewChainRequest(
		TABLE_NAT,
		NAT_CHAIN,
		rules, true,
	))

	return chains
}
