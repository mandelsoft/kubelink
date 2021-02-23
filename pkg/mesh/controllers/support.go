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
	"fmt"
	"reflect"
	"sort"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile/reconcilers"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/gardener/controller-manager-library/pkg/resources/abstract"
	"github.com/gardener/controller-manager-library/pkg/resources/filter"
	"github.com/gardener/controller-manager-library/pkg/types"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type Objects = map[resources.ClusterObjectKey]resources.Object

type ObjectHandler func(logger logger.LogContext, obj resources.Object, key resources.ClusterObjectKey) reconcile.Status

type SlaveResourceInfo struct {
	slaveRes    resources.Interface
	slaveFilter resources.KeyFilter
	slaveType   reflect.Type
}

func SlaveResource(gk schema.GroupKind, optcluster ...string) resources.ClusterGroupKind {
	cluster := controller.CLUSTER_MAIN
	if len(optcluster) != 0 {
		cluster = optcluster[0]
	}
	return abstract.NewClusterGroupKind(cluster, gk)
}

func NewSlaveResourceInfo(c controller.Interface, kind resources.ClusterGroupKind) (*SlaveResourceInfo, error) {
	cluster := controller.CLUSTER_MAIN
	if kind.Cluster != "" {
		cluster = kind.Cluster
	}
	cl := c.GetCluster(cluster)
	if cl == nil {
		return nil, fmt.Errorf("invalid cluster %q for slave def %s", cluster, kind.GroupKind)
	}
	kind.Cluster = cl.GetId()
	r, err := cl.Resources().Get(kind.GroupKind)
	if err != nil {
		return nil, err
	}
	return &SlaveResourceInfo{
		slaveRes:    r,
		slaveType:   r.ObjectType(),
		slaveFilter: filter.ClusterGroupKindFilter(kind),
	}, nil
}

type ReconcilerWithSlaves struct {
	reconcilers.ReconcilerSupport
	defSlave       *SlaveResourceInfo
	slaveByGK      map[schema.GroupKind]*SlaveResourceInfo
	slaveByType    map[reflect.Type]*SlaveResourceInfo
	slaveCache     *reconcilers.SimpleSlaveCache
	slaveFilter    resources.KeyFilter
	cleanupHandler ObjectHandler
}

func NewReconcilerWithSlave(c controller.Interface, gk schema.GroupKind, cleanup ObjectHandler) (ReconcilerWithSlaves, error) {
	return NewReconcilerWithSlaves(c, cleanup, resources.ClusterGroupKind{"", gk})
}

func NewReconcilerWithSlaves(c controller.Interface, cleanup ObjectHandler, slaves ...resources.ClusterGroupKind) (ReconcilerWithSlaves, error) {
	var defSlave *SlaveResourceInfo
	var filters []filter.KeyFilter
	gks := map[schema.GroupKind]*SlaveResourceInfo{}
	types := map[reflect.Type]*SlaveResourceInfo{}
	for _, s := range slaves {
		def, err := NewSlaveResourceInfo(c, s)
		if err != nil {
			return ReconcilerWithSlaves{}, err
		}
		if defSlave == nil {
			defSlave = def
		}
		filters = append(filters, def.slaveFilter)
		gks[def.slaveRes.GroupKind()] = def
		types[def.slaveRes.ObjectType()] = def
	}

	return ReconcilerWithSlaves{
		ReconcilerSupport: reconcilers.NewReconcilerSupport(c),
		defSlave:          defSlave,
		slaveByGK:         gks,
		slaveByType:       types,
		slaveFilter:       filter.Or(filters...),
		slaveCache:        reconcilers.GetSharedSimpleSlaveCache(c),
		cleanupHandler:    cleanup,
	}, nil
}

func (this *ReconcilerWithSlaves) SlaveCache() *reconcilers.SimpleSlaveCache {
	return this.slaveCache
}

func (this *ReconcilerWithSlaves) SlaveResources() map[schema.GroupKind]*SlaveResourceInfo {
	return this.slaveByGK
}

func (this *ReconcilerWithSlaves) CleanupObsoleteSlaves(logger logger.LogContext, qualifier *string, slaves map[resources.ClusterObjectKey]resources.Object) (resources.Object, error) {
	var found resources.Object
	msg := ""
	if qualifier != nil {
		msg = "additional "
		tmp := *qualifier
		if tmp != "" {
			tmp += " "
		}
		qualifier = &tmp
	}
	for _, o := range slaves {
		if qualifier == nil || found != nil {
			logger.Infof("checking slave %s", o.Key())
			if qualifier == nil || o.GetCreationTimestamp().Time.Before(found.GetCreationTimestamp().Time) {
			} else {
				found, o = o, found
			}
			err := o.Delete()
			if err == nil {
				err = this.Controller().RemoveFinalizer(o)
			}
			if err != nil && errors.IsNotFound(err) {
				err = nil
			}
			if err != nil {
				logger.Warnf("cleanup of obsolete %s%s %s failed %s", msg, o.GroupKind().Kind, o.ObjectName(), err)
				return nil, err
			} else {
				logger.Infof("cleanup of obsolete %s%s %s", msg, o.GroupKind().Kind, o.ObjectName())
			}
		} else {
			found = o
		}
	}
	if qualifier != nil {
		if found != nil {
			logger.Infof("found %s%s %s", *qualifier, found.GroupKind(), found.GetName())
		} else {
			logger.Infof("no %s slave found", *qualifier)
		}
	}
	return found, nil
}

func (this *ReconcilerWithSlaves) LookupSlaves(owner resources.ClusterObjectKey, keyFilter ...resources.KeyFilter) (Objects, error) {
	if len(keyFilter) == 0 {
		keyFilter = []resources.KeyFilter{this.defSlave.slaveFilter}
	}
	keys := this.slaveCache.GetSlavesFor(owner, keyFilter[0])
	return this.LookupObjects(keys)
}

func (this *ReconcilerWithSlaves) CreateSlave(owner resources.Object, data resources.ObjectData) (resources.Object, error) {

	s := this.slaveByType[reflect.TypeOf(data).Elem()]
	if s == nil {
		panic(fmt.Sprintf("unknown slave type %T", data))
	}
	slave, _ := s.slaveRes.Wrap(data)
	slave.SetFinalizers([]string{this.Controller().FinalizerHandler().FinalizerName(slave)})
	return slave, this.SlaveCache().CreateSlaveFor(owner, slave)
}

func (this *ReconcilerWithSlaves) LookupObjects(keys resources.ClusterObjectKeySet) (Objects, error) {
	result := Objects{}
	for k := range keys {
		obj, err := this.Controller().GetCachedObject(k)
		if err != nil {
			if !errors.IsNotFound(err) {
				return nil, err
			}
		}
		result[k] = obj
	}
	return result, nil
}

func (this *ReconcilerWithSlaves) DeleteSlaves(logger logger.LogContext, obj resources.Object, keyFilter resources.KeyFilter) reconcile.Status {
	slaves, err := this.LookupObjects(this.slaveCache.GetSlavesFor(obj.ClusterKey(), keyFilter))
	if err == nil {
		_, err = this.CleanupObsoleteSlaves(logger, nil, slaves)
	}
	if err == nil {
		err = this.Controller().RemoveFinalizer(obj)
		if err != nil && errors.IsNotFound(err) {
			err = nil
		}
	}
	return reconcile.DelayOnError(logger, err)
}

func (this *ReconcilerWithSlaves) Delete(logger logger.LogContext, obj resources.Object) reconcile.Status {
	logger.Infof("delete")
	if this.cleanupHandler != nil {
		status := this.cleanupHandler(logger, obj, obj.ClusterKey())
		if !status.IsSucceeded() {
			return status
		}
	}
	return this.DeleteSlaves(logger, obj, this.slaveFilter)
}

func (this *ReconcilerWithSlaves) Deleted(logger logger.LogContext, key resources.ClusterObjectKey) reconcile.Status {
	logger.Infof("deleted")
	if this.cleanupHandler != nil {
		return this.cleanupHandler(logger, nil, key)
	}
	return reconcile.Succeeded(logger)
}

////////////////////////////////////////////////////////////////////////////////

func AsKeySet(key resources.ClusterObjectKey) resources.ClusterObjectKeySet {
	if key.Name() == "" {
		return resources.NewClusterObjectKeySet()
	}
	return resources.NewClusterObjectKeySet(key)
}

func ClusterObjectKey(name string, gk schema.GroupKind, rel resources.Object) resources.ClusterObjectKey {
	return (&types.ObjectReference{Name: name}).ClusterKeyRelativeTo(rel, gk)
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

func CleanupMultiRefFinalizer(logger logger.LogContext, controller controller.Interface, usageCache *reconcilers.SimpleUsageCache,
	obj resources.Object, okey resources.ClusterObjectKey,
	localFilter, usedFilter resources.KeyFilter, extract func(obj resources.Object) resources.ClusterObjectKeySet,
	localKind, usedKind string) reconcile.Status {

	usedkeys := usageCache.GetFilteredUsesFor(okey, usedFilter)

	if obj == nil {
	} else {
		add := extract(obj)
		if usedkeys != nil {
			usedkeys.AddSet(add)
		} else {
			usedkeys = add
		}
	}
nextUsage:
	for key := range usedkeys {
		usageCache.Lock(nil, key)
		keys := usageCache.GetFilteredUsersFor(key, localFilter)
		logger.Infof("found %d %ss for %s %s", len(keys), localKind, usedKind, key.ObjectName())
		for k := range keys {
			if k != okey {
				usageCache.Unlock(key)
				continue nextUsage
			}
		}
		logger.Infof("no more other %ss for %s %s -> cleanup finalizer", localKind, usedKind, key.ObjectName())
		nw, err := controller.GetCachedObject(key)
		if err == nil {
			err = controller.RemoveFinalizer(nw)
		}
		usageCache.Unlock(key)
		if err != nil && !errors.IsNotFound(err) {
			return reconcile.Delay(logger, err)
		}
	}
	usageCache.UpdateUsesFor(okey, nil)
	return reconcile.Succeeded(logger)
}

func UpdateMultiRefFinalizer(logger logger.LogContext, controller controller.Interface, usageCache *reconcilers.SimpleUsageCache,
	obj resources.Object,
	localFilter, usedFilter resources.KeyFilter, extract func(obj resources.Object) resources.ClusterObjectKeySet,
	localKind, usedKind string) (resources.ClusterObjectKeySet, map[resources.ClusterObjectKey]resources.Object, error) {
	okey := obj.ClusterKey()

	usedkeys := usageCache.GetFilteredUsesFor(okey, usedFilter)
	required := extract(obj)

nextUsage:
	for key := range usedkeys {
		if required.Contains(key) {
			// still in use
			continue
		}
		// check usages
		usageCache.Lock(nil, key)
		keys := usageCache.GetFilteredUsersFor(key, localFilter)
		logger.Infof("found %d %ss for %s %s", len(keys), localKind, usedKind, key.ObjectName())
		for k := range keys {
			if k != okey {
				usageCache.Unlock(key)
				continue nextUsage
			}
		}
		logger.Infof("no more other %ss for %s %s -> cleanup finalizer", localKind, usedKind, key.ObjectName())
		nw, err := controller.GetCachedObject(key)
		if err == nil {
			err = controller.RemoveFinalizer(nw)
		}
		usageCache.Unlock(key)
		if err != nil && !errors.IsNotFound(err) {
			return required, nil, err
		}
	}
	found := map[resources.ClusterObjectKey]resources.Object{}
	for key := range required {
		req, err := controller.GetCachedObject(key)
		if err == nil {
			err = controller.SetFinalizer(req)
			found[key] = req
		}
	}
	usageCache.UpdateUsesFor(okey, required)
	return required, found, nil
}
