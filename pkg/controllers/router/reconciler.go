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

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/vishvananda/netlink"

	"github.com/mandelsoft/k8sbridge/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/k8sbridge/pkg/controllers"
	"github.com/mandelsoft/k8sbridge/pkg/kubelink"
)

type reconciler struct {
	*controllers.Reconciler
	config *Config
}

var _ reconcile.Interface = &reconciler{}
var _ controllers.ReconcilerImplementation = &reconciler{}

///////////////////////////////////////////////////////////////////////////////

func (this *reconciler) Config(cfg interface{}) *controllers.Config {
	return &cfg.(*Config).Config
}

func (this *reconciler) Gateway(obj *v1alpha1.KubeLink) (net.IP, error) {
	return nil, nil
}

func (this *reconciler) UpdateGateway(link *v1alpha1.KubeLink) *string {
	return nil
}

func (this *reconciler) IsManagedRoute(r *netlink.Route) bool {
	return CheckManaged(r, this.config.PodCIDR)
}

func (this *reconciler) ActualRoutes() (kubelink.Routes, error) {
	return kubelink.ListRoutes(this.NodeInterface().Name)
}

func (this *reconciler) RequiredRoutes() kubelink.Routes {
	return this.Links().GetRoutes(this.NodeInterface())
}
