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
	"sync"

	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"

	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/iptables"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

type synched struct {
	lock sync.RWMutex
	impl *links
	*linksdata
}

func (this *synched) Setup(logger logger.LogContext, list []resources.Object) {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.impl.Setup(logger, list)
}

func (this *synched) SetGateway(ip net.IP) {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.impl.SetGateway(ip)
}

func (this *synched) GetGateway() net.IP {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.impl.GetGateway()
}

func (this *synched) LinkInfoUpdated(logger logger.LogContext, name LinkName, access *LinkAccessInfo, dns *LinkDNSInfo) *Link {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.impl.LinkInfoUpdated(logger, name, access, dns)
}

func (this *synched) UpdateLinkInfo(logger logger.LogContext, name LinkName, access *LinkAccessInfo, dns *LinkDNSInfo, pending bool) (*Link, bool) {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.impl.UpdateLinkInfo(logger, name, access, dns, pending)
}

func (this *synched) ReplaceLink(link *Link) *Link {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.impl.ReplaceLink(link)
}

func (this *synched) UpdateLink(klink *api.KubeLink) (*Link, bool, *Link, error) {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.impl.UpdateLink(klink)
}

func (this *synched) GetMeshMembersFor(name string) LinkNameSet {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.impl.GetMeshMembersFor(name)
}

func (this *synched) RemoveLink(name LinkName) {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.impl.RemoveLink(name)
}

func (this *synched) IsGatewayLink(name LinkName) bool {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.impl.IsGatewayLink(name)
}

func (this *synched) IsGateway(ip net.IP) bool {
	if ip == nil {
		return false
	}
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.impl.IsGateway(ip)
}

func (this *synched) LookupMeshGatewaysFor(ip net.IP) tcp.IPList {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.impl.LookupMeshGatewaysFor(ip)
}

func (this *synched) GetRoutes(ifce *InterfaceInfo) Routes {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.impl.GetRoutes(ifce)
}

func (this *synched) GetRoutesToLink(gateway net.IP, index int, nexthop net.IP) Routes {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.impl.GetRoutesToLink(gateway, index, nexthop)
}

func (this *synched) GetGatewayEgress(gateway net.IP, meshCIDR *net.IPNet) tcp.CIDRList {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.impl.GetGatewayEgress(gateway, meshCIDR)
}

func (this *synched) GetEgressChain(mesh *net.IPNet) *iptables.ChainRequest {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.impl.GetEgressChain(mesh)
}

func (this *synched) GetFirewallChains() iptables.Requests {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.impl.GetFirewallChains()
}

func (this *synched) GetNatChains(clusterAddresses tcp.CIDRList, linkName string) iptables.Requests {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.impl.GetNatChains(clusterAddresses, linkName)
}

func (this *synched) GetSNatChains(clusterAddresses tcp.CIDRList, linkName string) iptables.Requests {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.impl.GetSNatChains(clusterAddresses, linkName)
}

func (this *synched) RegisterLink(name LinkName, clusterCIDR *net.IPNet, fqdn string, cidr *net.IPNet) (*Link, error) {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.impl.RegisterLink(name, clusterCIDR, fqdn, cidr)
}

func (this *synched) Locked(f func(Links) error) error {
	this.lock.Lock()
	defer this.lock.Unlock()
	return f(this.impl)
}
