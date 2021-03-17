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
	"github.com/gardener/controller-manager-library/pkg/config"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/gardener/controller-manager-library/pkg/utils"
	"github.com/vishvananda/netlink"

	"github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/controllers"
	"github.com/mandelsoft/kubelink/pkg/iptables"
	"github.com/mandelsoft/kubelink/pkg/kubelink"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

type reconciler struct {
	*controllers.Reconciler
	config   *Config
	endpoint resources.ObjectName
}

var _ reconcile.Interface = &reconciler{}
var _ controllers.ReconcilerImplementation = &reconciler{}

///////////////////////////////////////////////////////////////////////////////

func (this *reconciler) BaseConfig(cfg config.OptionSource) *controllers.Config {
	return &cfg.(*Config).Config
}

func (this *reconciler) Gateway(obj *v1alpha1.KubeLink) (*controllers.LocalGatewayInfo, error) {
	return nil, nil
}

func (this *reconciler) GetLinkInfo(link *v1alpha1.KubeLink) *controllers.LinkInfo {
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

func (this *reconciler) RequiredIPTablesChains() iptables.Requests {

	if this.Links().HasWireguard() && !this.isGateway() {
		return iptables.Requests{} // no firewall settings on non-gateway nodes
	}
	return nil // no iptables update
}

func (this *reconciler) isGateway() bool {
	return this.Links().IsGateway(this.NodeInterface())
}

func (this *reconciler) HandleDelete(logger logger.LogContext, name kubelink.LinkName, obj resources.Object) (bool, error) {
	ok := obj == nil || !this.Controller().HasFinalizer(obj)
	if ok {
		this.Links().RemoveLink(name)
		this.TriggerUpdate()
	}
	return true, nil
}

func (this *reconciler) HandleReconcile(logger logger.LogContext, obj resources.Object, entry *kubelink.Link) (error, error) {
	return nil, nil
}

////////////////////////////////////////////////////////////////////////////////

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

func (this *reconciler) Reconcile(logger logger.LogContext, obj resources.Object) reconcile.Status {
	if obj.GroupKind() == controllers.ENDPOINTS {
		return this.ReconcileEndpoint(logger, obj)
	}
	return this.Reconciler.Reconcile(logger, obj)
}

func (this *reconciler) ReconcileEndpoint(logger logger.LogContext, obj resources.Object) reconcile.Status {
	if resources.EqualsObjectName(obj.ObjectName(), this.endpoint) {
		n := utils.NewNotifier(logger)
		eps := controllers.GetEndpoints(n, obj)
		switch len(eps) {
		case 0:
			n.Activate()
			logger.Warnf("no endpoint for broker service %q found", this.config.Service)
			this.Links().SetGateway(nil)
		case 1:
			if !this.Links().GetGateway().Equal(eps[0]) {
				n.Infof("found endpoint %s for broker service %q found", eps[0], this.config.Service)
				this.Links().SetGateway(eps[0])
			}
		default:
			n.Infof("invalid service definition for broker service: multiple endpoints found: %v", eps)
		}
	}
	return reconcile.Succeeded(logger)
}
