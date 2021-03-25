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

	"github.com/gardener/controller-manager-library/pkg/utils"

	"github.com/mandelsoft/kubelink/pkg/iptables"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

func DNatEmbedding() ([]RuleDef, utils.StringSet) {
	// touched tables
	tables := utils.NewStringSet(TABLE_NAT)
	return []RuleDef{
		RuleDef{TABLE_NAT, "PREROUTING",
			iptables.Rule{
				iptables.R_CommentOpt("kubelink service rules"),
				iptables.R_JumpChainOpt(DNAT_CHAIN),
			}, nil,
		},
		RuleDef{TABLE_NAT, "OUTPUT",
			iptables.Rule{
				iptables.R_CommentOpt("kubelink service rules"),
				iptables.R_JumpChainOpt(DNAT_CHAIN),
			}, nil,
		},
	}, tables
}

////////////////////////////////////////////////////////////////////////////////

const DNAT_CHAIN = CHAIN_PREFIX + "SERVICES"
const DNAT_SVC_CHAIN_PREFIX = CHAIN_PREFIX + "SVC-"
const DNAT_SVCPORT_CHAIN_PREFIX = CHAIN_PREFIX + "SEP-"

func (this *linksdata) GetServiceChains(clusterAddresses tcp.CIDRList) iptables.Requests {
	var svcchains iptables.Requests
	var rules iptables.Rules

	this.services.Visit(func(s *Service) bool {
		var clusterAddress *net.IPNet

		if len(s.Endpoints) == 0 {
			return true
		}

		for _, cidr := range clusterAddresses {
			if cidr.Contains(s.Address) {
				clusterAddress = cidr
				break
			}
		}
		if clusterAddress == nil {
			return true
		}

		natRules := iptables.Rules{
			iptables.Rule{
				iptables.R_CommentOpt(fmt.Sprintf("service %s %s", s.Key, s.Address)),
			},
		}
		// append service/port rules

		if len(s.Ports) == 0 {
			// a single endpoint chain for the service ip
			handlePort(s, nil, &natRules, &svcchains)
		} else {
			// dedicated endpoint chains for every port
			for _, p := range s.Ports {
				handlePort(s, &p, &natRules, &svcchains)
			}
		}

		chain := iptables.NewChainRequest(
			TABLE_NAT,
			DNAT_SVC_CHAIN_PREFIX+encodeName(s.Key),
			natRules, true)

		svcchains = append(svcchains, chain)

		rules = append(rules, iptables.Rule{
			iptables.R_JumpChainOpt(chain.Chain.Chain),
		})

		return true
	})

	var chains iptables.Requests
	chains = append(chains, svcchains...)
	chains = append(chains, iptables.NewChainRequest(
		TABLE_NAT,
		DNAT_CHAIN,
		rules, true,
	))

	return chains
}

func handlePort(s *Service, port *ServicePort, svcrules *iptables.Rules, svcchains *iptables.Requests) {
	eprules := iptables.Rules{
		iptables.Rule{
			iptables.R_CommentOpt(fmt.Sprintf("mesh service %s %s%s", s.Key, s.Address, port)),
		},
	}
	hash := s.Endpoints.Hash(port)
	hash.Write([]byte(s.Key))
	cnt := len(s.Endpoints)
	for i, ep := range s.Endpoints {
		var rule iptables.Rule
		if cnt-i > 1 {
			rule = iptables.Rule{
				iptables.R_ProbabilityOpt(1.0 / float64(cnt-i)),
			}
		}
		tgt := ep.Address.String() + ep.PortSuffix(port)
		rule = append(rule, iptables.R_DNATOpt(tgt))
		eprules = append(eprules, rule)
	}
	epchain := iptables.NewChainRequest(
		TABLE_NAT,
		DNAT_SVCPORT_CHAIN_PREFIX+encodeHash(hash),
		eprules, true)

	rule := iptables.Rule{
		iptables.R_DestOpt(s.Address.String()),
	}
	if port != nil {
		rule = append(rule, iptables.R_PortFilter(port.Protocol, port.Port)...)
	}
	rule = append(rule,
		iptables.R_JumpChainOpt(epchain.Chain.Chain))

	*svcrules = append(*svcrules, rule)
	*svcchains = append(*svcchains, epchain)
}