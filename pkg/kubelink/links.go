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
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/mandelsoft/k8sbridge/pkg/apis/kubelink/v1alpha1"
)

const DEFAULT_PORT = 80

type Link struct {
	Name           string
	CIDR           *net.IPNet
	ClusterAddress net.IP
	ClusterCIDR    *net.IPNet
	Gateway        net.IP
	Endpoint       string
}

func (this *Link) String() string {
	return fmt.Sprintf("%s[%s,%s]", this.Name, this.Endpoint)
}

////////////////////////////////////////////////////////////////////////////////

func LinkFor(link *v1alpha1.KubeLink) (*Link, error) {
	_, cidr, err := net.ParseCIDR(link.Spec.CIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid routing cidr %q: %s", link.Spec.CIDR, err)
	}
	ip, ccidr, err := net.ParseCIDR(link.Spec.ClusterAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid cluster address %q: %s", link.Spec.ClusterAddress, err)
	}
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
	l := &Link{
		Name:           link.Name,
		CIDR:           cidr,
		ClusterCIDR:    ccidr,
		ClusterAddress: ip,
		Gateway:        gateway,
		Endpoint:       link.Spec.Endpoint,
	}
	if strings.Index(l.Endpoint, ":") < 0 {
		l.Endpoint = fmt.Sprintf("%s:%d", l.Endpoint, DEFAULT_PORT)
	}
	return l, err
}

////////////////////////////////////////////////////////////////////////////////

var linksKey = ctxutil.SimpleKey("kubelinks")

func GetSharedLinks(controller controller.Interface) *Links {
	return controller.GetEnvironment().GetOrCreateSharedValue(linksKey, func() interface{} {
		return NewLinks()
	}).(*Links)
}

type Links struct {
	lock        sync.RWMutex
	initialized bool
	links       map[string]*Link
	endpoints   map[string]*Link
}

func NewLinks() *Links {
	return &Links{
		links: map[string]*Link{},
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
		this.updateLink(l.Data().(*v1alpha1.KubeLink))
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
	return this.links[name]
}

func (this *Links) updateLink(link *v1alpha1.KubeLink) (*Link, error) {
	l, err := LinkFor(link)
	if err != nil {
		return nil, err
	}
	old := this.links[link.Name]
	if old != nil && old.Endpoint != l.Endpoint {
		delete(this.endpoints, old.Endpoint)
	}
	this.links[link.Name] = l
	this.endpoints[l.Endpoint] = l
	return l, nil
}

func (this *Links) RemoveLink(name string) {
	this.lock.Lock()
	defer this.lock.Unlock()
	delete(this.links, name)
}

func (this *Links) DeleteLink(name string) {
	delete(this.links, name)
}

////////////////////////////////////////////////////////////////////////////////

func (this *Links) GetLinkForIP(ip net.IP) (*Link, *net.IPNet) {
	this.lock.RLock()
	defer this.lock.RUnlock()
	for _, l := range this.links {
		if l.ClusterAddress.Equal(ip) {
			return l, nil
		}
		if l.CIDR.Contains(ip) {
			return l, l.CIDR
		}
	}
	return nil, nil
}

func (this *Links) GetLinkForEndpoint(dnsname string) *Link {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.endpoints[dnsname]
}

func (this *Links) GetRoutes(ifce *NodeInterface) Routes {
	this.lock.RLock()
	defer this.lock.RUnlock()

	routes := Routes{}
	for _, l := range this.links {
		if !l.Gateway.Equal(ifce.IP) {
			r := netlink.Route{
				Dst:       l.CIDR,
				Gw:        l.Gateway,
				LinkIndex: ifce.Index,
			}
			routes.Add(r)

			r = netlink.Route{
				Dst:       l.ClusterCIDR,
				Gw:        l.Gateway,
				LinkIndex: ifce.Index,
			}
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
			r := netlink.Route{
				Dst:       l.CIDR,
				LinkIndex: link.Attrs().Index,
			}
			routes.Add(r)
		}
	}
	return routes
}
