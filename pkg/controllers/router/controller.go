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

	"github.com/mandelsoft/kubelink/pkg/controllers"
)

func init() {
	controllers.BaseController("router", &Config{}).
		Reconciler(Create).
		MustRegister()
}

///////////////////////////////////////////////////////////////////////////////

func Create(controller controller.Interface) (reconcile.Interface, error) {
	var err error

	this := &reconciler{}

	this.Reconciler, err = controllers.CreateBaseReconciler(controller, this)
	if err != nil {
		return nil, err
	}
	this.config = this.Reconciler.Config().(*Config)

	controller.Infof("using cidr for pods:  %s", this.config.PodCIDR)
	return this, nil
}
