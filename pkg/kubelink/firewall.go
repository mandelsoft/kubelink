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
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"hash"
	"net"
	"strings"

	"github.com/gardener/controller-manager-library/pkg/utils"

	"github.com/mandelsoft/kubelink/pkg/iptables"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

const CHAIN_PREFIX = "KUBELINK-"

const LINKS_CHAIN = CHAIN_PREFIX + "LINKS"
const TABLE_LINKS_CHAIN = "mangle"

const FIREWALL_CHAIN = CHAIN_PREFIX + "FIREWALL"
const TABLE_FIREWALL_CHAIN = "filter"

const DROP_CHAIN = CHAIN_PREFIX + "DROP"
const TABLE_DROP_CHAIN = TABLE_FIREWALL_CHAIN

const MARK_DROP_CHAIN = CHAIN_PREFIX + "MARK-DROP"
const TABLE_MARK_DROP_CHAIN = TABLE_LINKS_CHAIN

const FW_LINK_CHAIN_PREFIX = CHAIN_PREFIX + "FW-"
const GW_LINK_CHAIN_PREFIX = CHAIN_PREFIX + "GW-"
const TABLE_LINK_CHAIN = TABLE_MARK_DROP_CHAIN

const MARK_BIT = "0x1000"

const DROP_ACTION = "DROP" // MARK_DROP_CHAIN

type RuleDef struct {
	Table  string
	Chain  string
	Rule   iptables.Rule
	Before utils.StringSet
}

func FirewallEmbedding() ([]RuleDef, utils.StringSet) {
	// touched tables
	tables := utils.NewStringSet(TABLE_LINK_CHAIN)
	if DROP_ACTION == DROP_CHAIN {
		tables.Add(TABLE_FIREWALL_CHAIN)
	}

	opt := iptables.Opt("-m", "comment", "--comment", "kubelink firewall rules")
	var before utils.StringSet
	if TABLE_LINKS_CHAIN != "mangle" {
		before = utils.NewStringSet("KUBE-SERVICES")
	}
	if DROP_ACTION == MARK_DROP_CHAIN {
		return []RuleDef{
			RuleDef{TABLE_LINKS_CHAIN, "PREROUTING", iptables.Rule{opt, iptables.R_JumpChainOpt(LINKS_CHAIN)}, before},
			RuleDef{TABLE_FIREWALL_CHAIN, "FORWARD", iptables.Rule{opt, iptables.R_JumpChainOpt(FIREWALL_CHAIN)}, utils.NewStringSet("KUBE-FORWARD")},
			RuleDef{TABLE_FIREWALL_CHAIN, "OUTPUT", iptables.Rule{opt, iptables.R_JumpChainOpt(FIREWALL_CHAIN)}, nil},
		}, tables
	} else {
		return []RuleDef{
			RuleDef{TABLE_LINKS_CHAIN, "PREROUTING", iptables.Rule{opt, iptables.R_JumpChainOpt(LINKS_CHAIN)}, before},
		}, tables
	}
}

func (this *links) GetEgressChain(mesh *net.IPNet) *iptables.ChainRequest {
	rules := iptables.Rules{
		iptables.Rule{
			iptables.R_CommentOpt("firewall egress for link gateway " + mesh.String()),
		},
	}
	// allow all traffic forwarded to other links
	for _, e := range this.GetGatewayEgress(nil, mesh) {
		rules = append(rules, iptables.Rule{
			iptables.R_DestOpt(e),
			iptables.R_AcceptOpt(),
		})
	}
	return iptables.NewChainRequest(
		TABLE_LINK_CHAIN,
		GW_LINK_CHAIN_PREFIX+encodeName(mesh.String()),
		rules, true)
}

func (this *links) GetFirewallChains() iptables.Requests {
	egresses := map[string]bool{}
	var rules iptables.Rules
	var linkchains iptables.Requests
	this.links.Visit(func(l *Link) bool {
		ing := l.GetIngressChain()
		if ing != nil {
			mesh := tcp.CIDRNet(l.ClusterAddress)
			if !egresses[mesh.String()] {
				egresses[mesh.String()] = true
				egress := this.GetEgressChain(mesh)
				linkchains = append(linkchains, egress)
				rules = append(rules, iptables.Rule{
					iptables.R_SourceOpt(mesh.String()),
					iptables.R_JumpChainOpt(egress.Chain.Chain),
				})
			}
			linkchains = append(linkchains, ing)
			rules = append(rules, iptables.Rule{
				iptables.R_SourceOpt(tcp.IPtoCIDR(l.ClusterAddress.IP).String()),
				iptables.R_JumpChainOpt(ing.Chain.Chain),
			})
		}
		return true
	})
	var chains iptables.Requests
	if len(rules) > 0 {
		if DROP_ACTION == MARK_DROP_CHAIN {
			chains = append(chains, iptables.NewChainRequest(
				TABLE_DROP_CHAIN,
				DROP_CHAIN,
				iptables.Rules{
					iptables.Rule{
						iptables.R_SetXMarkOpt(fmt.Sprintf("0x0/%s", MARK_BIT)),
					},
					iptables.Rule{
						iptables.R_DropOpt(),
					},
				}, true,
			))
			chains = append(chains, iptables.NewChainRequest(
				TABLE_MARK_DROP_CHAIN,
				MARK_DROP_CHAIN,
				iptables.Rules{
					iptables.Rule{
						iptables.R_SetXMarkOpt(fmt.Sprintf("%s/%s", MARK_BIT)),
					},
				}, true,
			))
		}
		chains = append(chains, linkchains...)
		chains = append(chains, iptables.NewChainRequest(
			TABLE_LINKS_CHAIN,
			LINKS_CHAIN,
			rules, true,
		))
		if DROP_ACTION == MARK_DROP_CHAIN {
			chains = append(chains, iptables.NewChainRequest(
				TABLE_FIREWALL_CHAIN,
				FIREWALL_CHAIN,
				iptables.Rules{
					iptables.Rule{
						iptables.R_CheckMarkOpt(fmt.Sprintf("%s/%s", MARK_BIT, MARK_BIT)),
						iptables.R_DropOpt(),
					},
				}, true,
			))
		}
	}
	return chains
}

func encodeName(name string) string {
	sum := sha1.Sum([]byte(name))
	return strings.ToUpper(base64.URLEncoding.EncodeToString(sum[:12]))
}

func encodeHash(hash hash.Hash) string {
	h := strings.ToUpper(base64.URLEncoding.EncodeToString(hash.Sum(nil)))
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
