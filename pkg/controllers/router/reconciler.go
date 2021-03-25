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
	"fmt"
	"net"

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
	config      *Config
	endpoint    resources.ObjectName
	nodeGateway bool
	gatewayIfce *kubelink.InterfaceInfo
	gatewayIP   net.IP

	routeTargets tcp.CIDRList
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
	tunl, _ := netlink.LinkByName("tunl0")
	if route.Dst != nil {
		if this.config.PodCIDR.Contains(route.Dst.IP) {
			return false
		}
		if route.Src != nil {
			return false
		}
		if route.Gw != nil {
			if this.config.NodeCIDR.Contains(route.Gw) && (route.LinkIndex == this.NodeInterface().Index || (tunl != nil && route.LinkIndex == tunl.Attrs().Index)) {
				return true
			}
		}
		if !this.UseNodeGateway() {
			if route.LinkIndex == this.gatewayIfce.Index {
				return true
			}
		}
		for _, r := range routes {
			if tcp.EqualCIDR(route.Dst, r.Dst) {
				return true
			}
		}
		for _, r := range this.routeTargets {
			if tcp.EqualCIDR(route.Dst, r) {
				return true
			}
		}
	}
	return false
}

func (this *reconciler) ConfirmManagedRoutes(list tcp.CIDRList) {
	if this.config.DataFile == "" {
		return
	}
	if !list.Equivalent(this.routeTargets) {
		this.Controller().Infof("confirming routes: %s", list)
		this.routeTargets = list
		err := WriteRoutes(this.config.DataFile, list)
		if err != nil {
			this.Controller().Errorf("cannot write routes: %s", err)
		}
	}
}

func (this *reconciler) RequiredRoutes() kubelink.Routes {
	if this.UseNodeGateway() {
		return this.Links().GetRoutes(this.NodeInterface())
	}
	if this.gatewayIfce != nil {
		return this.Links().GetRoutesToLink(this.NodeIP(), this.gatewayIfce.Index, this.gatewayIP)
	}
	return kubelink.Routes{}
}

func (this *reconciler) RequiredFirewallChains() iptables.Requests {

	if this.Links().HasWireguard() && (!this.IsGatewayNode() || !this.UseNodeGateway()) {
		return iptables.Requests{} // no firewall settings on non-gateway nodes
	}
	return nil // no iptables update
}

func (this *reconciler) RequiredNATChains() iptables.Requests {
	if !this.IsGatewayNode() || !this.UseNodeGateway() {
		return iptables.Requests{} // no NAT settings on non-gateway nodes
	}
	return nil
}

func (this *reconciler) UseNodeGateway() bool {
	return this.nodeGateway
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
			n.Warnf("no endpoint for broker service %q found", this.config.Service)
			this.Links().SetGateway(nil)
		case 1:
			gw := eps[0].HostIP
			ep := eps[0].EndpointIP
			if gw == nil {
				if this.NodeCIDR().Contains(ep) {
					gw = ep
				}
			}
			if gw == nil {
				n.Infof("no gateway node found")
				break
			}
			if !tcp.EqualIP(this.Links().GetGateway(), gw) || !tcp.EqualIP(this.gatewayIP, ep) {
				n.Infof("found endpoint %s for broker service %q", eps[0], this.config.Service)
			}
			this.gatewayIP = ep

			if tcp.EqualIP(this.NodeIP(), gw) {
				// on gateway node
				if !tcp.EqualIP(this.Links().GetGateway(), gw) {
					n.Infof("running on gateway node now")
				}
				this.Links().SetGateway(gw)
				if gw.Equal(ep) {
					// host network for gateway
					if !this.nodeGateway {
						n.Infof("switching to node gateway mode")
					}
					this.gatewayIfce = nil
					this.nodeGateway = true
				} else {
					// pod network for gateway
					if this.nodeGateway {
						n.Infof("switching to pod gateway mode")
					}
					this.nodeGateway = false
					podIfce, err := kubelink.LookupPodInterface(nil, ep)
					if err == nil {
						if this.gatewayIfce == nil {
							n.Infof("found pod gateway interface %s", podIfce)
						} else {
							if podIfce.Index != this.gatewayIfce.Index {
								n.Infof("changing pod gateway interface to %s", podIfce)
							}
						}
						this.gatewayIfce = podIfce
					} else {
						this.gatewayIfce = podIfce
						return reconcile.Delay(logger, fmt.Errorf("cannot find pod interface on gateway node: %s", err))
					}
				}
			} else {
				if tcp.EqualIP(this.Links().GetGateway(), this.NodeIP()) {
					n.Infof("running on no gateway node now")
				}
				this.Links().SetGateway(gw)
				this.nodeGateway = true
			}

		default:
			n.Infof("invalid service definition for broker service: multiple endpoints found: %v", eps)
		}
	}
	return reconcile.Succeeded(logger)
}
