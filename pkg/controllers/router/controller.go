/*
 * Copyright 2020 SAP SE or an SAP affiliate company. All rights reserved.
 * This file is licensed under the Apache Software License, v. 2 except as noted
 * otherwise in the LICENSE file
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 *
 */

package router

import (
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/resources"

	"github.com/mandelsoft/kubelink/pkg/controllers"
)

func init() {
	controllers.BaseController("router", &Config{}).
		Reconciler(Create).
		//SelectedWatchByGK(controller.ObjectSelection(controller.ObjectByNameOption("service")), controllers.ENDPOINTS).
		SelectedWatchByGK(controller.LocalNamespaceSelection, controllers.ENDPOINTS).
		MustRegister()
}

///////////////////////////////////////////////////////////////////////////////

func Create(controller controller.Interface) (reconcile.Interface, error) {
	var err error

	this := &reconciler{}

	this.Reconciler, err = controllers.CreateBaseReconciler(controller, this, 0)
	if err != nil {
		return nil, err
	}
	this.config = this.Reconciler.Config().(*Config)
	this.endpoint = resources.NewObjectName(controller.GetEnvironment().Namespace(), this.config.Service)

	res, _ := controller.GetMainCluster().Resources().Get(controllers.SECRET)
	_, err = res.Get(this.endpoint)
	if err != nil {
		controller.Infof("broker service %q not found in namespace %s: %s", this.endpoint.Name(), this.endpoint.Namespace(), err)
	}
	controller.Infof("using endpoint from service %q in namespace %s", this.endpoint.Name(), this.endpoint.Namespace())
	controller.Infof("using cidr for pods:  %s", this.config.PodCIDR)
	return this, nil
}
