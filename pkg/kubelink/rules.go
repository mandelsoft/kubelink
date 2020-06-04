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

package kubelink

import (
	"github.com/coreos/go-iptables/iptables"
	"github.com/gardener/controller-manager-library/pkg/convert"
	"github.com/gardener/controller-manager-library/pkg/logger"
)

type Chain struct {
	Table string
	Chain string
	Rules StringLists
}

func (this *Chain) Add(r StringList) *Chain {
	this.Rules = append(this.Rules, r)
	return this
}

func (this *Chain) Update(logger logger.LogContext, ipt *iptables.IPTables) error {
	if this == nil {
		return nil
	}
	if ipt == nil {
		var err error
		ipt, err = iptables.New()
		if err != nil {
			return err
		}
	}
	chains, err := ipt.ListChains(this.Table)
	if err != nil {
		return err
	}
	if StringList(chains).Index(this.Chain) < 0 {
		err := ipt.NewChain(this.Table, this.Chain)
		if err != nil {
			return err
		}
	}
	list, err := ipt.List(this.Table, this.Chain)
	if err != nil {
		return err
	}

	var cur StringLists
	if t, _ := convert.ConvertTo(list, StringLists{}); t!=nil {
		cur = t.(StringLists)
	}
	found := 0
	for _, e := range cur {
		if this.Rules.Index(e) < 0 {
			logger.Infof("chain %s/%s: deleting rule %v", this.Table, this.Chain, e)
			ipt.Delete(this.Table, this.Chain, e...)
		} else {
			found++
		}
	}
	for _, e := range this.Rules {
		if cur.Index(e) < 0 {
			logger.Infof("chain %s/%s: appending rule %v", this.Table, this.Chain, e)
			ipt.Append(this.Table, this.Chain, e...)
		}
	}
	if found == len(this.Rules) {
		logger.Infof("chain %s/%s: %d rules are up to date", this.Table, this.Chain, found)
	}
	return nil
}
