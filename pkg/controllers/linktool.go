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

func isJumpRule(r iptables.Rule, targets utils.StringSet) string {
	for target := range targets {
		if r.Index(iptables.Opt("-j", target)) >= 0 {
			return target
		}
	}
	return ""
}

func (this *LinkTool) AssureRule(logger utils.NotificationLogger, tname string, cname string, r iptables.Rule, before utils.StringSet) error {
	ok, err := this.ipt.Exists(tname, cname, r.AsList()...)
	if err != nil {
		return err
	}
	if ok {
		if len(before) == 0 {
			return nil
		}
		logger.Debugf("checking position before %q: %s", before, r)
		chain, err := this.ipt.ListChain(tname, cname)
		if err != nil {
			return err
		}
		for _, f := range chain.Rules {
			if f.Equals(r) {
				logger.Debugf("already before %q", before)
				return nil
			}
			if found := isJumpRule(f, before); found != "" {
				logger.Infof("currently after %q ", found)
				logger.Infof("deleting rule %s", r)
				err = this.ipt.DeleteRule(tname, cname, r)
				if err != nil {
					return err
				}
				break
			}
		}

	}
	if len(before) != 0 {
		logger.Infof("inserting rule %s", r)
		return this.ipt.InsertRule(tname, cname, 1, r)
	} else {
		logger.Infof("appending rule %s", r)
		return this.ipt.AppendRule(tname, cname, r)
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

func (this *LinkTool) DeleteChain(logger utils.NotificationLogger, t string, c string) error {
	logger.Infof("deleting chain %s/%s", t, c)
	return this.ipt.DeleteChain(t, c)
}

func (this *LinkTool) ClearChain(logger utils.NotificationLogger, t string, c string) error {
	logger.Infof("clearing chain %s/%s", t, c)
	return this.ipt.ClearChain(t, c)
}

func (this *LinkTool) AssureChains(logger utils.NotificationLogger, header string, chains iptables.Requests, cleanup ...string) error {
	for _, c := range chains {
		err := this.ChainRequest(logger, c)
		if err != nil {
			return err
		}
	}
	n := utils.NewNotifier(logger, header)
	if len(cleanup) > 0 {
		cleanupPrefix := cleanup[0]
		if len(cleanup) == 1 {
			cleanup = []string{"mangle", "nat"}
		} else {
			cleanup = cleanup[1:]
		}

		if cleanupPrefix != "" {
			for _, t := range cleanup {
				list, err := this.ListChains(t)
				if err != nil {
					return err
				}
				err = this.handle(n, cleanupPrefix, t, chains, list, this.ClearChain)
				if err != nil {
					return err
				}

				err = this.handle(n, cleanupPrefix, t, chains, list, this.DeleteChain)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (this *LinkTool) handle(logger utils.NotificationLogger, cleanupPrefix string, table string, chains iptables.Requests,
	found []string, f func(utils.NotificationLogger, string, string) error) error {
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

func (this *LinkTool) ChainRequest(logger utils.NotificationLogger, req *iptables.ChainRequest) error {
	return this.ipt.Execute(logger, req)
}

func (this *LinkTool) PrepareLink(logger logger.LogContext, link netlink.Link, clusterAddresses tcp.CIDRList) (func(), error) {
	if link == nil {
		return nil, nil
	}
	err := this.UpdateLinkAddresses(logger, link, clusterAddresses)
	return func() { this.HandleNat(logger, nil) }, err
}

func (this *LinkTool) UpdateLinkAddresses(logger logger.LogContext, link netlink.Link, addrs tcp.CIDRList) error {
	current, _ := netlink.AddrList(link, netlink.FAMILY_V4)
	found := map[string]*net.IPNet{}
	for _, a := range current {
		cidr := addrs.Lookup(a.IP)
		if cidr != nil {
			if tcp.EqualCIDR(a.IPNet, cidr) {
				found[cidr.String()] = cidr
			} else {
				logger.Infof("deleting outdated link address %q to %s", a, link.Attrs().Name)
				err := netlink.AddrDel(link, &a)
				if err != nil {
					logger.Errorf("cannot remove old link address %q", a.IPNet)
				}
			}
		} else {
			logger.Infof("deleting unused link address %q to %s", a, link.Attrs().Name)
			netlink.AddrDel(link, &a)
		}
	}

	for _, a := range addrs {
		if found[a.String()] == nil {
			nladdr := &netlink.Addr{
				IPNet: a,
			}
			logger.Infof("adding link address %q to %s", a, link.Attrs().Name)
			err := netlink.AddrReplace(link, nladdr)
			if err != nil {
				return fmt.Errorf("cannot add addr %q to %s: %s", a, link.Attrs().Name, err)
			}
		}
	}

	err := netlink.LinkSetUp(link)
	if err != nil {
		return fmt.Errorf("cannot bring up %q: %s", link.Attrs().Name, err)
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
	return this.ManageChains(logger, "firewall", kubelink.FirewallEmbedding, chains)
}

func (this *LinkTool) HandleNat(logger logger.LogContext, chains iptables.Requests) error {
	return this.ManageChains(logger, "nat", kubelink.NatEmbedding, chains)
}

type EmbeddingFunction func() ([]kubelink.RuleDef, utils.StringSet)

func (this *LinkTool) ManageChains(logger logger.LogContext, area string, embed EmbeddingFunction, chains iptables.Requests) error {
	for _, c := range chains {
		logger.Debugf("%s [%s]:", c.Chain.Chain, c.Table)
		for _, r := range c.Rules {
			logger.Debugf("  %s", r)
		}
	}
	embedding, tables := embed()
	if len(chains) == 0 {
		// deleting of the embedding works only with direct rule matches
		// to enable slightly changed embeddings first potential target rules are checked.
		// basically an embedding should not contain logic but just a jump to the
		// implementing main rule
		n := utils.NewNotifier(logger, fmt.Sprintf("remove %s embedding (%d rules)", area, len(embedding)))
		for _, e := range embedding {
			var target string
			var err error
			// lookup jump target
			if opt := e.Rule.GetOption("-j"); opt != nil {
				target = opt.AsArgs()[1]
			}
			if target != "" {
				// if target found delete any such target rule for compatibility
				var cur *iptables.Chain
				cur, err = this.ipt.ListChain(e.Table, e.Chain)
				if err == nil {
					opt := iptables.Opt("-j", target)
					for _, r := range cur.Rules {
						if r.Index(opt) >= 0 {
							if err = this.DeleteRule(e.Table, e.Chain, r); err == nil {
								n.Activate()
							}
						}
					}
					continue
				}
			}
			if err != nil || target == "" {
				// if match cannot be done just try the new version of the target rule
				if err := this.DeleteRule(e.Table, e.Chain, e.Rule); err == nil {
					n.Activate()
				}
			}
		}
	}
	err := this.AssureChains(logger, fmt.Sprintf("handle %d %s chain(s)", len(chains), area),
		chains, append([]string{kubelink.CHAIN_PREFIX}, tables.AsArray()...)...)
	if err != nil {
		return err
	}
	if len(chains) > 0 {
		n := utils.NewNotifier(logger, fmt.Sprintf("add %s embedding (%d rules)", area, len(embedding)))
		for _, e := range embedding {
			err = this.AssureRule(n, e.Table, e.Chain, e.Rule, e.Before)
			if err != nil {
				n.Activate()
				return err
			}
		}
	}
	return nil
}
