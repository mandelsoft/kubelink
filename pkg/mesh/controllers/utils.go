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
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/gardener/controller-manager-library/pkg/resources/filter"
	ipamapi "github.com/mandelsoft/kubipam/pkg/apis/ipam/v1alpha1"
	"github.com/mandelsoft/kubipam/pkg/ipam"

	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
)

var SECRET = resources.NewGroupKind("core", "Secret")

var FilterMembers = filter.GroupKindFilter(api.MEMBER)
var FilterMeshes = filter.GroupKindFilter(api.MESH)
var FilterSecrets = filter.GroupKindFilter(api.MESH)

func ConsumeIPAMs(slaves map[resources.ClusterObjectKey]resources.Object, size int) Objects {
	result := Objects{}
	for k, obj := range slaves {
		spec := &obj.Data().(*ipamapi.IPAMRange).Spec
		ranges, err := ipam.ParseIPRanges(spec.Ranges...)
		if err == nil && len(ranges) > 0 {
			if len(ranges[0].Start) == size {
				result[k] = obj
				delete(slaves, k)
			}
		}
	}
	return result
}

func ConsumeRequests(slaves map[resources.ClusterObjectKey]resources.Object, ipam resources.Object) Objects {
	if ipam == nil {
		return nil
	}
	result := Objects{}
	for k, obj := range slaves {
		spec := &obj.Data().(*ipamapi.IPAMRequest).Spec
		if ipam.GetName() == spec.IPAM.Name && (ipam.GetNamespace() == k.Namespace() || ipam.GetNamespace() == spec.IPAM.Namespace) {
			result[k] = obj
			delete(slaves, k)
		}
	}
	return result
}
