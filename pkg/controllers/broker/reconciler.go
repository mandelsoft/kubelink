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

package broker

import (
	"fmt"
	"net"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/ctxutil"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/vishvananda/netlink"

	"github.com/mandelsoft/k8sbridge/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/k8sbridge/pkg/controllers"
	"github.com/mandelsoft/k8sbridge/pkg/kubelink"
)

type reconciler struct {
	*controllers.Reconciler
	config *Config
	mux    *Mux
}

var _ reconcile.Interface = &reconciler{}
var _ controllers.ReconcilerImplementation = &reconciler{}

///////////////////////////////////////////////////////////////////////////////

func (this *reconciler) Config(cfg interface{}) *controllers.Config {
	return &cfg.(*Config).Config
}

func (this *reconciler) Gateway(obj *v1alpha1.KubeLink) (net.IP, error) {
	gateway := this.NodeInterface().IP
	match, ip := this.config.MatchLink(obj)
	if !match {
		return nil, nil
	}
	return gateway, this.mux.GetError(ip)
}

func (this *reconciler) UpdateGateway(link *v1alpha1.KubeLink) *string {
	gateway := this.NodeInterface().IP
	match, _ := this.config.MatchLink(link)
	if !match {
		gateway = nil
	}

	if gateway != nil {
		s := gateway.String()
		return &s
	}
	return nil
}

func (this *reconciler) ActualRoutes() (kubelink.Routes, error) {
	return kubelink.ListRoutes(this.mux.tun.link.Attrs().Name)
}

func (this *reconciler) IsManagedRoute(r *netlink.Route) bool {
	return CheckManaged(r, this.mux.tun.link.Attrs().Index)
}

func (this *reconciler) RequiredRoutes() kubelink.Routes {
	routes := this.Links().GetRoutesToLink(this.NodeInterface(), this.mux.tun.link)
	return append(routes, netlink.Route{LinkIndex: this.mux.tun.link.Attrs().Index, Dst: this.config.ClusterCIDR})
}

///////////////////////////////////////////////////////////////////////////////

func (this *reconciler) Setup() {
	this.Reconciler.Setup()
	tun, err := NewTun(this.Controller(), this.config.ClusterAddress, this.config.ClusterCIDR)
	if err != nil {
		panic(fmt.Errorf("cannot setup tun device: %s", err))
	}
	var local []net.IPNet
	if this.config.ServiceCIDR != nil {
		local = append(local, *this.config.ServiceCIDR)
	}
	mux := NewMux(this.Controller().GetContext(), this.Controller(), local, tun, this.Links(), this)
	go func() {
		<-this.Controller().GetContext().Done()
		this.Controller().Infof("closing tun device %q", tun)
		tun.Close()
	}()
	this.mux = mux
}

func (this *reconciler) Start() {
	NewServer("broker", this.mux).Start(nil, "", this.config.Port)
	go func() {
		defer ctxutil.Cancel(this.Controller().GetContext())
		this.Controller().Infof("starting tun server")
		err := this.mux.HandleTun()
		if err != nil {
			this.Controller().Errorf("tun handling aborted: %s", err)
		} else {
			this.Controller().Errorf("tun server finished")
		}
	}()
}

func (this *reconciler) NotifyFailed(l *kubelink.Link, err error) {
	this.Controller().Infof("requeue kubelink %q for failure handling: %s", l.Name, err)
	this.Controller().EnqueueKey(resources.NewClusterKey(this.Controller().GetMainCluster().GetId(), v1alpha1.KUBELINK, "", l.Name))
}
