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
	"regexp"

	"github.com/coreos/go-iptables/iptables"
	"github.com/gardener/controller-manager-library/pkg/logger"
)

type IPTables struct {
	*iptables.IPTables
}

func New() (*IPTables, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, err
	}
	return &IPTables{ipt}, nil
}

var fields = regexp.MustCompile(`[^\s"]+|"([^"]*)"`)

func Fields(line string) []string {
	fields := fields.FindAllString(line, -1)

	for i, f := range fields {
		if len(f) >= 2 {
			if f[0] == '"' && f[len(f)-1] == '"' {
				fields[i] = f[1 : len(f)-1]
			}
		}
	}
	return fields
}

// CleanupChain deletes all rules in the specified table/chain
// and finally deletes the chain
func (this *IPTables) CleanupChain(table, chain string) error {
	list, err := this.ListChains(table)
	if err == nil && StringList(list).Index(chain) >= 0 {
		err = this.IPTables.ClearChain(table, chain)
		if err == nil {
			this.IPTables.DeleteChain(table, chain)
		}
	}
	return err
}

func (this *IPTables) ListChain(table, chain string) (*Chain, error) {
	list, err := this.IPTables.List(table, chain)
	if err != nil {
		return nil, err
	}
	var rules Rules
	for _, l := range list {
		rule := ParseRule(Fields(l)...)
		//fmt.Printf("line:   %s\n", l)
		//fmt.Printf("fields: %s\n", Fields(l))
		//fmt.Printf("rule:   %s\n", rule)
		if !rule.HasOption("-N") {
			rule.RemoveOption("-A")
			rules.Add(rule)
			fmt.Printf("found %s\n", rule)
		}
	}
	return &Chain{
		Table: table,
		Chain: chain,
		Rules: rules,
	}, nil
}

func (this *IPTables) Execute(logger logger.LogContext, req *ChainRequest) error {
	return req.update(logger, this, req.Cleanup)
}

func (this *IPTables) UpdateChain(logger logger.LogContext, chain *Chain) error {
	return chain.update(logger, this, true)
}

func (this *IPTables) AssureChain(logger logger.LogContext, chain *Chain) error {
	return chain.update(logger, this, false)
}

func (this *IPTables) InsertRule(table, chain string, pos int, rule Rule) error {
	return this.Insert(table, chain, pos, rule.AsList()...)
}

func (this *IPTables) AppendRule(table, chain string, rule Rule) error {
	return this.Append(table, chain, rule.AsList()...)
}

func (this *IPTables) DeleteRule(table, chain string, rule Rule) error {
	return this.Delete(table, chain, rule.AsList()...)
}
