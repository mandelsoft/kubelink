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
	"sort"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile/reconcilers"
	"github.com/gardener/controller-manager-library/pkg/resources"

	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/kubelink"
)

func ObjectName(name kubelink.LinkName) resources.ObjectName {
	n := name.Name()
	if name.Mesh() != kubelink.DEFAULT_MESH {
		n = name.String()
	}
	return resources.NewObjectName(n)
}

func IsLocalLink(klink *api.KubeLink) bool {
	return klink.Spec.Endpoint == kubelink.EP_LOCAL
}

// TODO: moved to cm lib

func AsKeySet(key resources.ClusterObjectKey) resources.ClusterObjectKeySet {
	if key.Name() == "" {
		return resources.NewClusterObjectKeySet()
	}
	return resources.NewClusterObjectKeySet(key)
}

// LockAndUpdateFilteredUsage updates the usage of an object of a dedicated kind for a single used object
// the used object is locked and an unlock function returned
func LockAndUpdateFilteredUsage(usageCache *reconcilers.SimpleUsageCache, user resources.ClusterObjectKey, filter resources.KeyFilter, used resources.ClusterObjectKey) func() {
	usageCache.Lock(nil, used)
	usageCache.UpdateFilteredUsesFor(user, filter, resources.NewClusterObjectKeySet(used))
	return func() { usageCache.Unlock(used) }
}

// LockAndUpdateFilteredUsages updates the usage of an object of a dedicated kind
// the used object is locked and an unlock function returned
func LockAndUpdateFilteredUsages(usageCache *reconcilers.SimpleUsageCache, user resources.ClusterObjectKey, filter resources.KeyFilter, used resources.ClusterObjectKeySet) func() {
	keys := used.AsArray()
	sort.Sort(keys)
	for _, key := range keys {
		usageCache.Lock(nil, key)
	}
	usageCache.UpdateFilteredUsesFor(user, filter, used)
	return func() {
		for _, key := range keys {
			usageCache.Unlock(key)
		}
	}
}
