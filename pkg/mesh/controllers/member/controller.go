/*
 * Copyright 2021 Mandelsoft. All rights reserved.
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

package member

import (
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile/reconcilers"
	"github.com/gardener/controller-manager-library/pkg/resources/apiextensions"

	ipamapi "github.com/mandelsoft/kubipam/pkg/apis/ipam/v1alpha1"

	"github.com/mandelsoft/kubelink/pkg/apis/kubelink/crds"
	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/mesh/controllers"
	"github.com/mandelsoft/kubelink/pkg/mesh/controllers/mesh"
	"github.com/mandelsoft/kubelink/pkg/mesh/database"
)

const NAME = "member"

func init() {
	crds.AddToRegistry(apiextensions.DefaultRegistry())

	controller.Configure(NAME).
		RequireLease().After(mesh.NAME).
		FinalizerDomain("mandelsoft.org").
		DefaultWorkerPool(2, 0).
		OptionsByExample("options", &Config{}).
		MainResourceByGK(api.MEMBER).
		Reconciler(Create).
		With(reconcilers.SlaveReconcilerForGKs("ipam", controller.CLUSTER_MAIN, ipamapi.IPAMREQUEST)).
		With(reconcilers.UsageReconcilerForGKs("usage", controller.CLUSTER_MAIN, api.MESH, api.MEMBER)).
		MustRegister()
}

func Create(c controller.Interface) (reconcile.Interface, error) {
	cfg, err := c.GetOptionSource("options")
	if err != nil {
		return nil, err
	}
	this := &reconciler{
		config:     cfg.(*Config),
		usageCache: reconcilers.GetSharedSimpleUsageCache(c),
	}
	base, err := controllers.NewReconcilerWithSlave(c, ipamapi.IPAMREQUEST, this.cleanupHandler)
	if err != nil {
		return nil, err
	}
	this.ReconcilerWithSlaves = base
	this.database = database.GetDatabase(c)
	this.membres, err = c.GetMainCluster().Resources().Get(api.MEMBER)
	this.ipamres, err = c.GetMainCluster().Resources().Get(ipamapi.IPAMRANGE)
	this.meshres, err = c.GetMainCluster().Resources().Get(api.MESH)
	return this, err
}
