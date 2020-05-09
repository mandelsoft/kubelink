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
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/cluster"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/ctxutil"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

const DEFAULT_PORT = 80

////////////////////////////////////////////////////////////////////////////////

type Link struct {
	lock           sync.Mutex
	Name           string
	ServiceCIDR    *net.IPNet
	Egress         tcp.CIDRList
	Ingress        tcp.CIDRList
	ClusterAddress *net.IPNet
	Gateway        net.IP
	Host           string
	Endpoint       string
	LinkForeignData
}

type LinkAccessInfo struct {
	CACert string
	Token  string
}

type LinkForeignData struct {
	UpdatePending bool
	LinkAccessInfo
}

func (this *Link) Release() {
	if this != nil {
		this.lock.Unlock()
	}
}

func (this *Link) String() string {
	return fmt.Sprintf("%s[%s,%s,%s]", this.Name, this.ClusterAddress, this.Egress, this.Endpoint)
}

func (this *Link) AllowIngress(ip net.IP) (granted bool, set bool) {
	if !this.Ingress.IsSet() {
		return true, false
	}
	return this.Ingress.Contains(ip), true
}

////////////////////////////////////////////////////////////////////////////////

func (this *Links) LinkFor(link *v1alpha1.KubeLink) (*Link, error) {
	var egress tcp.CIDRList
	var serviceCIDR *net.IPNet

	if !Empty(link.Spec.CIDR) {
		_, cidr, err := net.ParseCIDR(link.Spec.CIDR)
		if err != nil {
			return nil, fmt.Errorf("invalid routing cidr %q: %s", link.Spec.CIDR, err)
		}
		serviceCIDR = cidr
		egress.Add(cidr)
	}
	for _, c := range link.Spec.Egress {
		_, cidr, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("invalid routing cidr %q: %s", link.Spec.CIDR, err)
		}
		egress.Add(cidr)
	}
	var ingress tcp.CIDRList

	for _, c := range link.Spec.Ingress {
		_, cidr, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("invalid routing cidr %q: %s", link.Spec.CIDR, err)
		}
		ingress.Add(cidr)
	}

	ip, ccidr, err := net.ParseCIDR(link.Spec.ClusterAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid cluster address %q: %s", link.Spec.ClusterAddress, err)
	}
	ccidr.IP = ip
	if link.Spec.Endpoint == "" {
		return nil, fmt.Errorf("no endpoint")
	}
	if link.Status.Gateway == "" {
		return nil, fmt.Errorf("no gateway address")
	}
	gateway := net.ParseIP(link.Status.Gateway)
	if gateway == nil {
		return nil, fmt.Errorf("invalid gateway address %q", link.Status.Gateway)
	}
	endpoint := link.Spec.Endpoint
	parts := strings.Split(endpoint, ":")
	if len(parts) == 1 {
		endpoint = fmt.Sprintf("%s:%d", endpoint, DEFAULT_PORT)
	}

	l := &Link{
		Name:           link.Name,
		ServiceCIDR:    serviceCIDR,
		Egress:         egress,
		Ingress:        ingress,
		ClusterAddress: ccidr,
		Gateway:        gateway,
		Host:           parts[0],
		Endpoint:       endpoint,
	}
	return l, err
}

////////////////////////////////////////////////////////////////////////////////

var linksKey = ctxutil.SimpleKey("kubelinks")

func GetSharedLinks(controller controller.Interface) *Links {
	return controller.GetEnvironment().GetOrCreateSharedValue(linksKey, func() interface{} {
		resc, err := controller.GetMainCluster().Resources().Get(&v1alpha1.KubeLink{})
		if err != nil {
			controller.Errorf("cannot get kubelink resource: %s", err)
		}
		return NewLinks(resc)
	}).(*Links)
}

type Links struct {
	lock        sync.RWMutex
	resource    resources.Interface
	initialized bool
	links       map[string]*Link
	endpoints   map[string]*Link
	clusteraddr map[string]*Link
}

func NewLinks(resc resources.Interface) *Links {
	return &Links{
		resource:    resc,
		links:       map[string]*Link{},
		endpoints:   map[string]*Link{},
		clusteraddr: map[string]*Link{},
	}
}

func (this *Links) Setup(logger logger.LogContext, cluster cluster.Interface) {
	this.lock.Lock()
	defer this.lock.Unlock()

	if this.initialized {
		return
	}
	this.initialized = true
	if logger != nil {
		logger.Infof("setup links")
	}
	res, _ := cluster.Resources().Get(v1alpha1.KUBELINK)
	list, _ := res.ListCached(labels.Everything())

	for _, l := range list {
		link, err := this.updateLink(l.Data().(*v1alpha1.KubeLink))
		if link != nil {
			logger.Infof("found link %s", link)
			link.Release()
		}
		if err != nil {
			logger.Infof("errorneous link %s: %s", l.GetName(), err)
		}
	}
}

func (this *Links) UpdateLink(link *v1alpha1.KubeLink) (*Link, error) {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.updateLink(link)
}

func (this *Links) GetLink(name string) *Link {
	this.lock.Lock()
	defer this.lock.Unlock()
	l := this.links[name]
	if l != nil {
		l.lock.Lock()
	}
	return l
}

func (this *Links) updateLink(link *v1alpha1.KubeLink) (*Link, error) {
	l, err := this.LinkFor(link)
	if err != nil {
		return nil, err
	}
	old := this.links[link.Name]
	if old != nil {
		old.lock.Lock()
		if old.Host != l.Host {
			delete(this.endpoints, old.Host)
		}
		if !old.ClusterAddress.IP.Equal(l.ClusterAddress.IP) {
			delete(this.clusteraddr, old.ClusterAddress.IP.String())
		}
		l.LinkForeignData = old.LinkForeignData
		old.Release()
	}
	this.links[link.Name] = l
	this.endpoints[l.Host] = l
	this.clusteraddr[l.ClusterAddress.IP.String()] = l
	l.lock.Lock()
	return l, nil
}

func (this *Links) RemoveLink(name string) {
	this.lock.Lock()
	defer this.lock.Unlock()
	l := this.links[name]
	if l != nil {
		delete(this.links, name)
		delete(this.endpoints, l.Host)
		delete(this.clusteraddr, l.ClusterAddress.IP.String())
	}
}

func (this *Links) Visit(visitor func(l *Link) bool) {
	for _, l := range this.links {
		if !visitor(l) {
			break
		}
	}
}

////////////////////////////////////////////////////////////////////////////////

func (this *Links) GetLinkForIP(ip net.IP) *Link {
	this.lock.RLock()
	defer this.lock.RUnlock()

	if l := this.clusteraddr[ip.String()]; l != nil {
		return l
	}
	for _, l := range this.links {
		if l.Egress.Contains(ip) {
			return l
		}
	}
	return nil
}

func (this *Links) GetLinkForClusterAddress(ip net.IP) *Link {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.clusteraddr[ip.String()]
}

func (this *Links) GetLinkForEndpoint(dnsname string) *Link {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.endpoints[dnsname]
}

func (this *Links) GetRoutes(ifce *NodeInterface) Routes {
	this.lock.RLock()
	defer this.lock.RUnlock()

	var flags netlink.NextHopFlag
	index := ifce.Index
	protocol := 0
	i, err := netlink.LinkByName("tunl0")
	if i != nil && err == nil {
		index = i.Attrs().Index
		fmt.Printf("*** found tun10[%d]\n", index)
		flags = netlink.FLAG_ONLINK
	}
	routes := Routes{}
	for _, l := range this.links {
		if !l.Gateway.Equal(ifce.IP) {
			for _, c := range l.Egress {
				r := netlink.Route{
					Dst:       c,
					Gw:        l.Gateway,
					LinkIndex: index,
					Protocol:  protocol,
				}
				r.SetFlag(flags)
				routes.Add(r)
			}
			r := netlink.Route{
				Dst:       tcp.CIDRNet(l.ClusterAddress),
				Gw:        l.Gateway,
				LinkIndex: index,
				Protocol:  protocol,
			}
			r.SetFlag(flags)
			routes.Add(r)
		}
	}
	return routes
}

func (this *Links) GetRoutesToLink(ifce *NodeInterface, link netlink.Link) Routes {
	this.lock.RLock()
	defer this.lock.RUnlock()

	routes := Routes{}
	for _, l := range this.links {
		if l.Gateway.Equal(ifce.IP) {
			for _, c := range l.Egress {
				r := netlink.Route{
					Dst:       c,
					LinkIndex: link.Attrs().Index,
				}
				routes.Add(r)
			}
		}
	}
	return routes
}

func (this *Links) RegisterLink(name string, clusterCIDR *net.IPNet, fqdn string, cidr *net.IPNet) (*Link, error) {
	kl := &v1alpha1.KubeLink{}
	kl.Name = name
	kl.Spec.ClusterAddress = clusterCIDR.IP.String()
	kl.Spec.Endpoint = fqdn
	kl.Spec.CIDR = cidr.String()
	_, err := this.resource.Create(kl)
	if err != nil {
		return nil, err
	}
	return this.UpdateLink(kl)
}
