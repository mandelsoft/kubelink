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
	"net"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/ctxutil"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/gardener/controller-manager-library/pkg/utils"

	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/iptables"

	//"github.com/mandelsoft/kubelink/pkg/controllers/broker/config"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

const DEFAULT_PORT = 80

const CLUSTER_DNS_IP = 10
const KUBELINK_DNS_IP = 11

const DNSMODE_NONE = "none"
const DNSMODE_KUBERNETES = "kubernetes"
const DNSMODE_DNS = "dns"

////////////////////////////////////////////////////////////////////////////////

var linksKey = ctxutil.SimpleKey("kubelinks")

func GetSharedLinks(controller controller.Interface, defaultport int) Links {
	return controller.GetEnvironment().GetOrCreateSharedValue(linksKey, func() interface{} {
		resc, err := controller.GetMainCluster().Resources().Get(&api.KubeLink{})
		if err != nil {
			controller.Errorf("cannot get kubelink resource: %s", err)
		}
		return NewLinks(resc, defaultport)
	}).(Links)
}

type Links interface {
	Setup(logger logger.LogContext, list []resources.Object)
	SetDefaultMesh(clusterName string, clusterAddress *net.IPNet, meshDNS LinkDNSInfo)

	SetGateway(ip net.IP)
	GetGateway() net.IP
	IsGateway(ip net.IP) bool

	IsGatewayLink(name LinkName) bool
	HasWireguard() bool
	RegisterLink(name LinkName, clusterCIDR *net.IPNet, fqdn string, cidr *net.IPNet) (*Link, error)

	GetLinks() map[LinkName]*Link
	GetLink(name LinkName) *Link
	LinkInfoUpdated(logger logger.LogContext, name LinkName, access *LinkAccessInfo, dns *LinkDNSInfo) *Link
	UpdateLinkInfo(logger logger.LogContext, name LinkName, access *LinkAccessInfo, dns *LinkDNSInfo, pending bool) (*Link, bool)
	ReplaceLink(link *Link) *Link
	UpdateLink(klink *api.KubeLink) (*Link, bool, *Link, error)
	RemoveLink(name LinkName)
	VisitLinks(visitor func(l *Link) bool)
	GetLinkForClusterAddress(ip net.IP) *Link
	GetLinkForIP(ip net.IP) *Link // TODO Rename
	GetLinkForEndpointHost(dnsname string) *Link

	ServedLinksFor(name LinkName) LinkNameSet

	GetMesh(name string) *Mesh
	GetStaleMesh(name string) *LinkName
	GetMeshByLinkName(name LinkName) *Mesh
	GetMeshLink(name LinkName) *Link
	GetMeshLinks() map[LinkName]*Link
	GetMeshInfos() map[string]*Mesh
	GetMeshMembersFor(name string) LinkNameSet
	RemoveMesh(name string)
	MarkForDeletion(name LinkName)
	VisitMeshes(visitor func(m *Mesh, l *Link) bool)

	LookupMeshGatewaysFor(ip net.IP) tcp.IPList
	LookupClusterAddressByMeshAddress(ip net.IP) *net.IPNet
	LookupMeshByMeshAddress(ip net.IP) *Mesh

	GetRoutesToLink(gateway net.IP, linkIndex int, nexthop net.IP) Routes
	GetRoutes(ifce *InterfaceInfo) Routes
	GetGatewayEgress(gateway net.IP, meshCIDR *net.IPNet) tcp.CIDRList

	GetFirewallChains() iptables.Requests
	GetEgressChain(mesh *net.IPNet) *iptables.ChainRequest
	GetNatChains(clusterAddresses tcp.CIDRList, linkName string) iptables.Requests
	GetSNatChains(clusterAddresses tcp.CIDRList, linkName string) iptables.Requests
	GetGatewayAddrs() tcp.CIDRList

	UpdateService(svc *Service)
	GetServices() map[string]*Service
	GetService(key string) *Service
	GetServiceForAddress(ip net.IP) *Service
	VisitServices(visitor func(l *Service) bool)
	GetServiceChains(clusterAddresses tcp.CIDRList) iptables.Requests

	Locked(func(Links) error) error
}

func NewLinks(resc resources.Interface, defaultport int) Links {
	links := &links{
		resource:    resc,
		defaultport: defaultport,
		linksdata:   newData(),
	}
	return &synched{
		linksdata: links.linksdata,
		impl:      links,
	}
}

func NatEmbedding() ([]RuleDef, utils.StringSet) {
	rules, tables := SNatEmbedding()
	dnat, dtab := DNatEmbedding()
	return append(rules, dnat...), tables.AddSet(dtab)
}
