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

package iptables

import (
	"fmt"

	"github.com/gardener/controller-manager-library/pkg/utils"
)

type ChainRequest struct {
	*Chain
	Cleanup bool
}

func NewChainRequest(table, chain string, rules Rules, cleanup bool) *ChainRequest {
	return &ChainRequest{
		Chain: &Chain{
			Table: table,
			Chain: chain,
			Rules: rules,
		},
		Cleanup: cleanup,
	}
}

func (this *ChainRequest) String() string {
	s := fmt.Sprintf("  *%s(%t)", this.Chain.Chain, this.Cleanup)
	for _, r := range this.Rules {
		s = fmt.Sprintf("%s\n    %s", s, utils.Strings(r.AsList()...))
	}
	return s
}

type Requests []*ChainRequest

func (this Requests) String() string {
	s := "["
	for _, c := range this {
		s = fmt.Sprintf("%s\n%s", s, c)
	}
	return s + "\n]"
}
