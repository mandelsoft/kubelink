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
	"io/ioutil"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"

	_apps "k8s.io/api/apps/v1"
	_core "k8s.io/api/core/v1"

	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/controllers"
	"github.com/mandelsoft/kubelink/pkg/controllers/broker/config"
	"github.com/mandelsoft/kubelink/pkg/kubelink"
	"github.com/mandelsoft/kubelink/pkg/tasks"
	kutils "github.com/mandelsoft/kubelink/pkg/utils"
)

func init() {
	_ = _apps.Deployment{}

	controllers.BaseController("broker", &config.Config{}).
		RequireLease().
		FinalizerDomain("kubelink.mandelsoft.org").
		//	WatchesByGK(api.MESHSERVICE, controllers.SERVICE).
		Reconciler(Create).With(controllers.SecretCacheReconciler).
		With(tasks.TaskReconciler(3)).
		MustRegister()
}

///////////////////////////////////////////////////////////////////////////////

func Create(controller controller.Interface) (reconcile.Interface, error) {
	cfg, err := controller.GetOptionSource("options")
	if err != nil {
		return nil, err
	}
	this := &reconciler{
		secrets: controllers.GetSharedSecrets(controller),
		config:  cfg.(*config.Config),
	}

	var impl controllers.ReconcilerImplementation
	if this.config.Mode == config.RUN_MODE_NONE {
		impl = &dummy{}
	} else {
		impl = this
	}

	this.tasks = tasks.GetTaskClient(controller)

	this.Reconciler, err = controllers.CreateBaseReconciler(controller, impl, DefaultPort(this.config.Mode))
	if err != nil {
		return nil, err
	}

	if this.NodeInterface() == nil {
		if this.config.NodeIP == nil {
			return nil, fmt.Errorf("node ip required for pod mode")
		}
		err = this.SetNodeIP(this.config.NodeIP)
		if err != nil {
			return nil, err
		}
		controller.Infof("broker running in pod mode (%s)", this.NetworkInterface())
		data, err := ioutil.ReadFile("/proc/sys/net/ipv4/ip_forward")
		if err != nil {
			return nil, fmt.Errorf("cannot detect ip forwarding: %s", err)
		}
		if len(data) < 1 || data[0] != '1' {
			controller.Infof("enable ip forwarding in pod")
			err = ioutil.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte{'1'}, 0666)
			if err != nil {
				return nil, fmt.Errorf("cannot enable ip forwarding: %s", err)
			}
		}
	} else {
		controller.Infof("broker running in node mode")
	}

	controller.Infof("setting gateway ip to %s", this.NodeIP())
	this.Links().SetGateway(this.NodeIP())

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

	controller.Infof("using runmode %s", this.config.Mode)
	this.runmode, err = CreateRunMode(this.config.Mode, this)
	if err != nil {
		return nil, err
	}

	if this.config.ServiceAccount != nil {
		controller.Infof("advertise api access with service account %q", this.config.ServiceAccount)

		access, err := this.getServiceAccountToken()
		if err != nil {
			return nil, fmt.Errorf("cannot get service account token: %s", err)
		}
		if access != nil {
			this.access = *access
			controller.Infof("  found access: %s", this.access)
		}
	} else {
		controller.Infof("api access advertisement disabled")
	}

	this.dnsInfo.ClusterDomain = this.config.ClusterDomain
	this.dnsInfo.DnsIP = this.config.DNSServiceIP
	this.dnsInfo.DNSPropagation = this.config.DNSPropagation != config.DNSMODE_NONE
	if this.config.DNSAdvertisement {
		controller.Infof("advertise dns access with with dns IP %s and cluster domain %s", this.dnsInfo.DnsIP, this.dnsInfo.ClusterDomain)
	} else {
		controller.Infof("dns access advertisement disabled")
	}

	if this.dnsInfo.DNSPropagation {
		controller.Infof("enable dns propagation (%s)", this.config.DNSPropagation)
		controller.Infof("  local cluster domain %q", this.dnsInfo.ClusterDomain)
		if this.dnsInfo.DnsIP != nil {
			controller.Infof("  local dns ip %q", this.dnsInfo.DnsIP)
		}
		controller.Infof("  handle coredns deployment %q", this.config.CoreDNSDeployment)
		controller.Infof("  using coredns secret %q", this.config.CoreDNSSecret)
		controller.Infof("  default mesh domain %q", this.config.MeshDomain)
		if this.config.CoreDNSConfigure {
			controller.Infof("  automatic configuration of cluster local coredns setup")
			if this.config.CoreDNSServiceIP != nil {
				controller.Infof("    using coredns service IP %q", this.config.CoreDNSServiceIP)
			}
		}
	} else {
		controller.Infof("dns propagation disabled")
	}

	if this.config.ClusterAddress != nil {
		meshDNS := kubelink.LinkDNSInfo{
			ClusterDomain:  this.config.MeshDomain,
			DnsIP:          this.config.MeshDNSServiceIP,
			DNSPropagation: this.dnsInfo.DNSPropagation,
		}

		controller.Infof("using default mesh settings")
		controller.Infof("  cluster address: %s", this.config.ClusterAddress)
		controller.Infof("  cluster name: %s", this.config.ClusterName)
		controller.Infof("  mesh domain %q", this.config.MeshDomain)
		if this.config.MeshDNSServiceIP != nil {
			controller.Infof("  global mesh dns %s", this.config.MeshDNSServiceIP)
		}

		this.Links().SetDefaultMesh(this.config.ClusterName, this.config.ClusterAddress, meshDNS)
	}
	controller.Infof("serving links: %s", this.config.Responsible)
	if !kutils.Empty(this.config.Secret) {
		controller.Infof("using TLS secret %q with management mode %s", this.config.Secret, this.config.ManageMode)
	}
	if this.config.Interface == "" {
		controller.Infof("using dynamic interface name")
	} else {
		controller.Infof("using interface name: %s", this.config.Interface)
	}

	return this, nil
}
