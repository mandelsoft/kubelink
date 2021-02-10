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

package router

import (
	"net"

	"github.com/gardener/controller-manager-library/pkg/config"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/vishvananda/netlink"

	"github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/controllers"
	"github.com/mandelsoft/kubelink/pkg/iptables"
	"github.com/mandelsoft/kubelink/pkg/kubelink"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

type reconciler struct {
	*controllers.Reconciler
	config *Config
}

var _ reconcile.Interface = &reconciler{}
var _ controllers.ReconcilerImplementation = &reconciler{}

///////////////////////////////////////////////////////////////////////////////

func (this *reconciler) BaseConfig(cfg config.OptionSource) *controllers.Config {
	return &cfg.(*Config).Config
}

func (this *reconciler) Gateway(obj *v1alpha1.KubeLink) (net.IP, error) {
	return nil, nil
}

func (this *reconciler) UpdateGateway(link *v1alpha1.KubeLink) *string {
	return nil
}

func (this *reconciler) IsManagedRoute(route *netlink.Route, routes kubelink.Routes) bool {
	if route.Dst != nil {
		if this.config.PodCIDR.Contains(route.Dst.IP) {
			return false
		}
		if route.Gw != nil && route.LinkIndex == this.NodeInterface().Index {
			return true
		}
		for _, r := range routes {
			if tcp.EqualCIDR(route.Dst, r.Dst) {
				return true
			}
		}
	}
	return false
}

func (this *reconciler) RequiredRoutes() kubelink.Routes {
	return this.Links().GetRoutes(this.NodeInterface())
}

func (this *reconciler) RequiredSNATRules() iptables.Requests {
	return nil
	// return this.Links().GetSNATRules(this.NodeInterface())
}

func (this *reconciler) Setup() {
	switch this.config.IPIP {
	case controllers.IPIP_SHARED:
		this.WaitIPIP()
	case controllers.IPIP_CONFIGURE:
		err := this.SetupIPIP()
		if err != nil {
			panic(err)
		}
	}
	this.Reconciler.Setup()
}
