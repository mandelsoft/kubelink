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

package broker

import (
	"fmt"
	"net"
	"strings"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/intstr"

	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/controllers"
	"github.com/mandelsoft/kubelink/pkg/kubelink"
)

func (this *reconciler) reconcileMeshService(logger logger.LogContext, obj resources.Object) reconcile.Status {
	logger.Infof("start reconcile %d[%s]", obj.GetGeneration(), obj.GetResourceVersion())
	data := obj.Data().(*api.MeshService)

	if !this.Links().IsPodMode() {
		_, err := resources.UpdateStandardObjectStatus(logger, obj, api.STATE_UNSUPPORTED, "mesh services supported only for pod mode of kubelink")
		return reconcile.DelayOnError(logger, err)
	}

	key := obj.ClusterKey()
	defer controllers.LockAndUpdateFilteredUsages(this.usageCache, key, controllers.FilterServices, extractServiceUsageForMeshService(obj))()
	def, mesh, tmperr, err := this.validateMeshService(logger, data)

	this.updateMeshService(logger, key, mesh)

	if tmperr != nil {
		return reconcile.Delay(logger, tmperr)
	}
	if err != nil {
		_, tmperr = resources.UpdateStandardObjectStatus(logger, obj, api.STATE_INVALID, err.Error())
		return reconcile.DelayOnError(logger, tmperr)
	}

	old := this.Links().GetService(def.Key)
	if !def.Equal(old) {
		logger.Infof("updating mesh service")
		this.Links().UpdateService(def)
		this.TriggerUpdate()
	} else {
		logger.Infof("mesh service unchanged")
	}
	_, tmperr = resources.UpdateStandardObjectStatus(logger, obj, api.STATE_OK, "")
	return reconcile.DelayOnError(logger, tmperr)
}

func (this *reconciler) deleteMeshService(logger logger.LogContext, obj resources.Object, key resources.ClusterObjectKey) reconcile.Status {
	this.usageCache.UpdateUsesFor(key, nil)
	this.Links().RemoveService(fmt.Sprintf("%s.%s", key.Namespace, key.Name))
	return reconcile.Succeeded(logger)
}

func (this *reconciler) validateMeshService(logger logger.LogContext, svc *api.MeshService) (*kubelink.Service, string, error, error) {
	service := &kubelink.Service{
		Key: fmt.Sprintf("%s.%s", svc.Namespace, svc.Name),
	}
	// check address/mesh
	if svc.Spec.MeshAddress != "" {
		service.Address = net.ParseIP(svc.Spec.MeshAddress)
		if service.Address == nil {
			return nil, "", nil, fmt.Errorf("invalid ip for mesh service: %s", svc.Spec.MeshAddress)
		}
	} else {
		// TODO: reconcile on mesh creation
		service.Mesh = svc.Spec.Mesh
		if service.Mesh == "" {
			service.Mesh = kubelink.DEFAULT_MESH
		}
		if this.Links().GetMesh(service.Mesh) == nil {
			return nil, service.Mesh, nil, fmt.Errorf("unknown mesh: %s", service.Mesh)
		}
	}

	// check ports
	for _, p := range svc.Spec.Ports {
		if p.Port <= 0 {
			return nil, service.Mesh, nil, fmt.Errorf("invalid port %d", p.Port)
		}
		p.Protocol = strings.ToUpper(p.Protocol)
		if p.Protocol != api.PROTO_TCP && p.Protocol != api.PROTO_UDP && p.Protocol != "" {
			return nil, service.Mesh, nil, fmt.Errorf("invalid protocol for port %d: %s", p.Port, p.Protocol)
		}
		service.Ports = append(service.Ports, kubelink.ServicePort{
			Protocol: p.Protocol,
			Port:     p.Port,
		})
	}

	if len(service.Ports) == 0 && service.Address == nil {
		return nil, service.Mesh, nil, fmt.Errorf("shared local mesh member service requires explicit service ports")
	}

	// check service mode
	if svc.Spec.Service != "" {
		s, err := this.svcResource.GetCached(resources.NewObjectName(svc.Namespace, svc.Spec.Service))
		if err != nil {
			if errors.IsNotFound(err) {
				return nil, service.Mesh, nil, fmt.Errorf("backing service %q not found", svc.Spec.Service)
			}
			return nil, service.Mesh, err, nil
		}
		sdata := s.Data().(*corev1.Service)
		ip := net.ParseIP(sdata.Spec.ClusterIP)
		if ip == nil {
			return nil, service.Mesh, nil, fmt.Errorf("invalid cluster ip for service %q", svc.Spec.Service)
		}
		if len(svc.Spec.Endpoints) > 1 {
			return nil, service.Mesh, nil, fmt.Errorf("service can use only one endpoint")
		}
		var m kubelink.PortMappings
		if len(svc.Spec.Endpoints) == 1 {
			if svc.Spec.Endpoints[0].Address != "" {
				return nil, service.Mesh, nil, fmt.Errorf("for service mode no endpoint address possible")
			}
			m, err = getPortMappings(svc.Spec.Endpoints[0].PortMappings, service.Ports, sdata.Spec.Ports)
			if err != nil {
				return nil, service.Mesh, nil, err
			}
		}
		if m == nil {
			if service.Address == nil {
				return nil, service.Mesh, nil, fmt.Errorf("shared local mesh member service requires explicit port mappings for kubernetes service %q", svc.Spec.Service)
			}
		}
		service.Endpoints = kubelink.ServiceEndpoints{
			kubelink.ServiceEndpoint{
				Address:      ip,
				PortMappings: m,
			},
		}
	} else {
		if len(svc.Spec.Endpoints) == 0 {
			return nil, service.Mesh, nil, fmt.Errorf("service or endpoints missing")
		}
		for i, ep := range svc.Spec.Endpoints {
			ip := net.ParseIP(ep.Address)
			if ip == nil {
				return nil, service.Mesh, nil, fmt.Errorf("invalid ip for endpoint %d", i)
			}
			mappings, err := getPortMappings(ep.PortMappings, service.Ports, nil)
			if err != nil {
				return nil, service.Mesh, nil, err
			}
			service.Endpoints = append(service.Endpoints, kubelink.ServiceEndpoint{
				Address:      ip,
				PortMappings: mappings,
			})
		}
	}
	service.Normalize()
	return service, service.Mesh, nil, nil
}

func getPortMappings(mappings []api.PortMapping, ports kubelink.ServicePorts, val []corev1.ServicePort) (kubelink.PortMappings, error) {
	var r kubelink.PortMappings
	for _, m := range mappings {
		proto := m.Protocol
		if proto == "" {
			proto = api.PROTO_TCP
		}

		// service port
		var port int32 = -1
		switch m.Port.Type {
		case intstr.Int:
			if m.Port.IntVal <= 0 {
				return nil, fmt.Errorf("invalid port %d in port mapping", m.Port.IntVal)
			}
			port = m.Port.IntVal
		case intstr.String:
			if val == nil {
				return nil, fmt.Errorf("port name requires service mode")
			}
			for _, v := range val {
				if v.Name == m.Port.StrVal && (proto == string(v.Protocol) || (proto == api.PROTO_TCP && v.Protocol == "")) {
					port = v.Port
					break
				}
			}
			if port < 0 {
				return nil, fmt.Errorf("%s port %q not found in service", proto, m.Port.StrVal)
			}
		}

		// target port
		var targetport int32 = -1
		switch m.TargetPort.Type {
		case intstr.Int:
			if m.TargetPort.IntVal <= 0 {
				return nil, fmt.Errorf("invalid target port %d in port mapping", m.TargetPort.IntVal)
			}
			targetport = m.TargetPort.IntVal
		case intstr.String:
			if val == nil {
				return nil, fmt.Errorf("port name requires service mode")
			}
			for _, v := range val {
				if v.Name == m.TargetPort.StrVal {
					targetport = v.Port
					break
				}
			}
			if targetport < 0 {
				return nil, fmt.Errorf("%s target port %q not found in service", proto, m.TargetPort.StrVal)
			}
		}

		found := false
		for _, p := range ports {
			if p.Port == port && (proto == p.Protocol || (proto == api.PROTO_TCP && p.Protocol == "")) {
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("mapping %s port %d not found in served ports", proto, port)
		}
		r = append(r, kubelink.PortMapping{
			Port: kubelink.ServicePort{
				Protocol: strings.ToLower(proto),
				Port:     port,
			},
			TargetPort: targetport,
		})
	}
	return r, nil
}
