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
	"github.com/gardener/controller-manager-library/pkg/logger"

	"github.com/mandelsoft/kubelink/pkg/utils"
)

type Chain struct {
	Table string
	Chain string
	Rules Rules
}

func (this *Chain) Index(r Rule) int {
	return this.Rules.Index(r)
}

func (this *Chain) Add(r Rule) *Chain {
	this.Rules.Add(r)
	return this
}

func (this *Chain) update(logger logger.LogContext, ipt *IPTables, cleanup bool) error {
	if this == nil {
		return nil
	}
	if ipt == nil {
		var err error
		ipt, err = New()
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
	cur, err := ipt.ListChain(this.Table, this.Chain)
	if err != nil {
		return err
	}

	// logger.Infof("chain %s/%s: found %d rules", this.Table, this.Chain, len(cur))
	found := Rules{}
	ccnt := 0
	dcnt := 0
	n := &utils.Notifier{LogContext: logger}
	for _, e := range cur.Rules {
		if this.Rules.Index(e) < 0 {
			if cleanup {
				dcnt++
				n.Add(true, "chain %s/%s: deleting rule %v", this.Table, this.Chain, e)
				ipt.DeleteRule(this.Table, this.Chain, e)
			}
		} else {
			if found.Index(e) >= 0 {
				dcnt++
				n.Add(true, "chain %s/%s: deleting duplicate rule %v", this.Table, this.Chain, e)
				ipt.DeleteRule(this.Table, this.Chain, e)
			} else {
				n.Add(dcnt > 0, "chain %s/%s: found rule %v", this.Table, this.Chain, e)
				found = append(found, e)
			}
		}
	}
	for _, e := range this.Rules {
		if cur.Index(e) < 0 {
			n.Add(true, "chain %s/%s: appending rule %v", this.Table, this.Chain, e)
			err := ipt.AppendRule(this.Table, this.Chain, e)
			if err != nil {
				return err
			}
		}
	}
	logger.Infof("chain %s/%s: %d managed (%d deleted) and %d created rules", this.Table, this.Chain, len(this.Rules), dcnt, ccnt)
	return nil
}
