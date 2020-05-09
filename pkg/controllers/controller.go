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

package controllers

import (
	"time"

	"github.com/gardener/controller-manager-library/pkg/config"
	"github.com/gardener/controller-manager-library/pkg/resources/apiextensions"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"

	"github.com/mandelsoft/kubelink/pkg/apis/kubelink/crds"
	"github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/kubelink"
)

const CMD_UPDATE = "update"

func init() {
	crds.AddToRegistry(apiextensions.DefaultRegistry())
}

func BaseController(name string, config config.OptionSource) controller.Configuration {
	return controller.Configure(name).
		DefaultWorkerPool(1, 0).
		OptionsByExample("options", config).
		MainResourceByGK(v1alpha1.KUBELINK).
		CustomResourceDefinitions(v1alpha1.KUBELINK).
		WorkerPool("update", 1, 20*time.Second).
		Commands(CMD_UPDATE)
}

///////////////////////////////////////////////////////////////////////////////

func CreateBaseReconciler(controller controller.Interface, impl ReconcilerImplementation) (*Reconciler, error) {
	cfg, err := controller.GetOptionSource("options")
	if err != nil {
		return nil, err
	}
	config := impl.Config(cfg)

	controller.Infof("using cidr for nodes: %s", config.NodeCIDR)

	ifce, err := kubelink.LookupNodeIP(controller, config.NodeCIDR)
	if err != nil {
		return nil, err
	}

	return &Reconciler{
		Common:     NewCommon(controller),
		config:     cfg,
		baseconfig: config,
		ifce:       ifce,
		links:      kubelink.GetSharedLinks(controller),
		impl:       impl,
	}, nil
}
