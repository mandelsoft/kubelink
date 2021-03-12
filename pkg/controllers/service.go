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

package controllers

import (
	"fmt"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/resources"
	corev1 "k8s.io/api/core/v1"
)

var SERVICE = resources.NewGroupKind("", "Service")

func GetServicePort(cntr controller.Interface, name string, kind string, proto corev1.Protocol) (int, error) {
	// analyse and validate service
	resc, err := cntr.GetMainCluster().GetResource(SERVICE)
	if err != nil {
		return 0, err
	}

	svc, err := resc.Get(resources.NewObjectName(cntr.GetEnvironment().ControllerManager().GetNamespace(), name))
	if err != nil {
		return 0, fmt.Errorf("%s service %q not found", kind, name)
	}
	s := svc.Data().(*corev1.Service)
	if len(s.Spec.Ports) != 1 {
		return 0, fmt.Errorf("%s service %q must define a single port", kind, name)
	}
	port := s.Spec.Ports[0]
	if port.Protocol != proto {
		return 0, fmt.Errorf("wireguard service %q must define an %s port", name, proto)
	}
	return int(port.Port), nil
}
