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

package controllers

import (
	"fmt"
	"net"
	"strings"

	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/utils"
	"github.com/vishvananda/netlink"

	"github.com/mandelsoft/kubelink/pkg/iptables"
	"github.com/mandelsoft/kubelink/pkg/kubelink"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

const IPTAB = "nat"
const IPCHAIN = "POSTROUTING"

type LinkTool struct {
	ipt *iptables.IPTables
}

func NewLinkTool() (*LinkTool, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("cannot create iptables access: %s", err)
	}
	return &LinkTool{
		ipt: ipt,
	}, nil
}

func (this *LinkTool) AssureRule(logger logger.LogContext, t string, c string, r iptables.Rule, before string) error {
	ok, err := this.ipt.Exists(t, c, r.AsList()...)
	if err != nil {
		return err
	}
	if ok {
		if before == "" {
			return nil
		}
		logger.Infof("checking position before %q: %s", before, r)
		chain, err := this.ipt.ListChain(t, c)
		if err != nil {
			return err
		}
		for _, f := range chain.Rules {
			if f.Equals(r) {
				logger.Infof("found %s before %q", r, before)
				return nil
			}
			if r.Index(iptables.Opt(".j", before)) >= 0 {
				logger.Infof("found %q before %s", before, r)
				err = this.ipt.DeleteRule(t, c, r)
				if err != nil {
					return err
				}
				break
			}
		}

	}
	if before != "" {
		return this.ipt.InsertRule(t, c, 1, r)
	} else {
		return this.ipt.AppendRule(t, c, r)
	}
	return nil
}

func (this *LinkTool) ExistsRule(t string, c string, r iptables.Rule) (bool, error) {
	return this.ipt.Exists(t, c, r.AsList()...)
}

func (this *LinkTool) AppendRule(t string, c string, r iptables.Rule) error {
	return this.ipt.AppendRule(t, c, r)
}

func (this *LinkTool) DeleteRule(t string, c string, r iptables.Rule) error {
	return this.ipt.DeleteRule(t, c, r)
}

func (this *LinkTool) ListChains(t string) ([]string, error) {
	return this.ipt.ListChains(t)
}

func (this *LinkTool) DeleteChain(logger logger.LogContext, t string, c string) error {
	logger.Infof("deleting chain %s/%s", t, c)
	return this.ipt.DeleteChain(t, c)
}

func (this *LinkTool) ClearChain(logger logger.LogContext, t string, c string) error {
	logger.Infof("clearing chain %s/%s", t, c)
	return this.ipt.ClearChain(t, c)
}

func (this *LinkTool) AssureChains(logger logger.LogContext, chains iptables.Requests, cleanup ...string) error {
	for _, c := range chains {
		err := this.ChainRequest(logger, c)
		if err != nil {
			return err
		}
	}
	if len(cleanup) > 0 {
		cleanupPrefix := cleanup[0]
		if len(cleanup) == 1 {
			cleanup = []string{"mangle", "filter"}
		} else {
			cleanup = cleanup[1:]
		}

		if cleanupPrefix != "" {
			for _, t := range cleanup {
				list, err := this.ListChains(t)
				if err != nil {
					return err
				}
				err = this.handle(logger, cleanupPrefix, t, chains, list, this.ClearChain)
				if err != nil {
					return err
				}

				err = this.handle(logger, cleanupPrefix, t, chains, list, this.DeleteChain)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (this *LinkTool) handle(logger logger.LogContext, cleanupPrefix string, table string, chains iptables.Requests,
	found []string, f func(logger.LogContext, string, string) error) error {
next:
	for _, l := range found {
		for _, c := range chains {
			if c.Chain.Chain == l && c.Table == table {
				continue next
			}
		}
		if strings.HasPrefix(l, cleanupPrefix) {
			err := f(logger, table, l)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
func (this *LinkTool) ChainRequest(logger logger.LogContext, req *iptables.ChainRequest) error {
	return this.ipt.Execute(logger, req)
}

func (this *LinkTool) NatRulesExists(rule ...string) (bool, error) {
	return this.ipt.Exists(IPTAB, IPCHAIN, rule...)
}

func (this *LinkTool) NatRulesAppend(rule ...string) error {
	return this.ipt.Append(IPTAB, IPCHAIN, rule...)
}

func (this *LinkTool) NatRulesDelete(rule ...string) error {
	return this.ipt.Append(IPTAB, IPCHAIN, rule...)
}

func (this *LinkTool) PrepareLink(link netlink.Link, clusterAddress *net.IPNet) error {
	name := link.Attrs().Name

	err := this.SetLinkAddress(link, clusterAddress)
	if err != nil {
		return err
	}

	rule := []string{"-o", name, "-j", "SNAT", "--to-source", clusterAddress.IP.String()}
	ok, err := this.ipt.Exists(IPTAB, IPCHAIN, rule...)
	if err != nil {
		return fmt.Errorf("cannot check nat: %s", err)
	}

	if !ok {
		err = this.ipt.Append(IPTAB, IPCHAIN, rule...)
		if err != nil {
			return fmt.Errorf("cannot add nat rule %v: %s", rule, err)
		}
		logger.Infof("added nat rule %v", rule)
	}
	return nil
}

func (this *LinkTool) SetLinkAddress(link netlink.Link, addr *net.IPNet) error {
	nladdr := &netlink.Addr{
		IPNet: addr,
	}

	addrs, _ := netlink.AddrList(link, netlink.FAMILY_V4)
	found := false
	for _, a := range addrs {
		if tcp.EqualCIDR(a.IPNet, addr) {
			found = true
		} else {
			if a.IP.Equal(addr.IP) {
				err := netlink.AddrDel(link, &a)
				if err != nil {
					logger.Errorf("cannot remove old link address %q", a.IPNet)
				}
			}
		}
	}

	if !found {
		err := netlink.AddrReplace(link, nladdr)
		if err != nil {
			return fmt.Errorf("cannot add addr %q to %s: %s", addr, link.Attrs().Name, err)
		}
	}

	err := netlink.LinkSetUp(link)
	if err != nil {
		return fmt.Errorf("cannot bring up %q: %s", link.Attrs().Name, err)
	}
	return nil
}

func (this *LinkTool) HandleFirewall(logger logger.LogContext, chains iptables.Requests) error {
	for _, c := range chains {
		logger.Debugf("%s [%s]:", c.Chain.Chain, c.Table)
		for _, r := range c.Rules {
			logger.Debugf("  %s", r)
		}
	}
	embedding := kubelink.FirewallEmbedding()
	if len(chains) == 0 {
		logger.Infof("remove embedding")
		for _, e := range embedding {
			this.DeleteRule(e.Table, e.Chain, e.Rule)
		}
	}
	logger.Infof("handle chains")
	set := utils.NewStringSet(kubelink.TABLE_LINK_CHAIN)
	if kubelink.DROP_ACTION == kubelink.DROP_CHAIN {
		set.Add(kubelink.TABLE_FIREWALL_CHAIN)
	}
	err := this.AssureChains(logger, chains, append([]string{kubelink.CHAIN_PREFIX}, set.AsArray()...)...)
	if err != nil {
		return err
	}
	if len(chains) > 0 {
		logger.Infof("add embedding")
		for _, e := range embedding {
			err = this.AssureRule(logger, e.Table, e.Chain, e.Rule, e.Before)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
