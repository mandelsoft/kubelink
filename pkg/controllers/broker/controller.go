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

package broker

import (
	"fmt"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/resources"

	_apps "k8s.io/api/apps/v1"
	_core "k8s.io/api/core/v1"

	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/controllers"
	"github.com/mandelsoft/kubelink/pkg/kubelink"
)

var secretGK = resources.NewGroupKind("", "Secret")

func init() {
	_ = _apps.Deployment{}

	controllers.BaseController("broker", &Config{}).
		RequireLease().
		Reconciler(Create).
		WorkerPool("secrets", 1, 0).
		Reconciler(CreateSecrets, "secrets").
		ReconcilerWatchByGK("secrets", secretGK).
		With(TaskReconciler(1)).
		MustRegister()
}

///////////////////////////////////////////////////////////////////////////////

func Create(controller controller.Interface) (reconcile.Interface, error) {

	this := &reconciler{
		secrets: GetSharedSecrets(controller),
	}

	cfg, err := controller.GetOptionSource("options")
	if err != nil {
		return nil, err
	}
	var impl controllers.ReconcilerImplementation
	if cfg.(*Config).DisableBridge {
		impl = &dummy{}
	} else {
		impl = this
	}

	this.tasks = GetTaskClient(controller)

	this.Reconciler, err = controllers.CreateBaseReconciler(controller, impl)
	if err != nil {
		return nil, err
	}
	this.config = this.Reconciler.Config().(*Config)

	r, err := controller.GetMainCluster().Resources().GetByExample(&api.KubeLink{})
	if err != nil {
		return nil, fmt.Errorf("no kubelink resource found: %s", err)
	}
	this.linkResource = r

	r, err = controller.GetMainCluster().Resources().GetByExample(&_core.ServiceAccount{})
	if err != nil {
		return nil, fmt.Errorf("no service account resource found: %s", err)
	}
	this.saResource = r

	r, err = controller.GetMainCluster().Resources().GetByExample(&_core.Secret{})
	if err != nil {
		return nil, fmt.Errorf("no secret resource found: %s", err)
	}
	this.secretResource = r

	r, err = controller.GetMainCluster().Resources().GetByExample(&_apps.Deployment{})
	if err != nil {
		return nil, fmt.Errorf("no deployment resource found: %s", err)
	}
	this.deploymentResource = r

	if this.config.DNSPropagation {
		if this.config.CoreServiceAccount != nil {
			controller.Infof("using dns propagation with service account %q", this.config.CoreServiceAccount)

			access, err := this.getServiceAccountToken()
			if err != nil {
				return nil, fmt.Errorf("cannot get service account token: %s", err)
			}
			if access != nil {
				this.access = *access
				controller.Infof("  found access: %s", this.access)
			}
		} else {
			controller.Infof("using dns propagation")
		}
		controller.Infof("  handle coredns deployment %q", this.config.CoreDNSDeployment)
		controller.Infof("  using coredns secret %q", this.config.CoreDNSSecret)
		if this.config.CoreDNSConfigure {
			controller.Infof("  automatic configuration of cluster local coredns setup")
			if this.config.CoreDNSServiceIP != nil {
				controller.Infof("  using coredns service IP %q", this.config.CoreDNSServiceIP)
			}
		}
	} else {
		controller.Infof("dns propagation disabled")
	}

	controller.Infof("using cluster cidr:  %s", this.config.ClusterCIDR)
	controller.Infof("using cluster address: %s", this.config.ClusterAddress)
	controller.Infof("serving links: %s", this.config.Responsible)
	if !kubelink.Empty(this.config.Secret) {
		controller.Infof("using TLS secret %q with management mode %s", this.config.Secret, this.config.ManageMode)
	}
	if this.config.Interface == "" {
		controller.Infof("using dynamic tun interface name")
	} else {
		controller.Infof("using tun interface name: %s", this.config.Interface)
	}

	return this, nil
}

///////////////////////////////////////////////////////////////////////////////

func CreateSecrets(controller controller.Interface) (reconcile.Interface, error) {
	this := &secretReconciler{
		Common: controllers.NewCommon(controller),
		cache:  GetSharedSecrets(controller),
	}
	return this, nil

}
