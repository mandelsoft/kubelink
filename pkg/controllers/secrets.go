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
	"reflect"
	"sync"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/ctxutil"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/gardener/controller-manager-library/pkg/utils"
)

var SECRET = resources.NewGroupKind("", "Secret")

type NotificationHandler interface {
	NotifyChange(name resources.ObjectName, object resources.Object)
}

func NotificationFunction(f func(resources.ObjectName, resources.Object)) NotificationHandler {
	return &notificationFunction{f}
}

type notificationFunction struct {
	f func(resources.ObjectName, resources.Object)
}

func (this *notificationFunction) NotifyChange(name resources.ObjectName, obj resources.Object) {
	this.f(name, obj)
}

type secretReconciler struct {
	Common
	cache *SecretCache
}

var _ reconcile.Interface = &secretReconciler{}

func SecretCacheReconciler(config controller.Configuration) controller.Configuration {
	return config.WorkerPool("secrets", 1, 0).
		Reconciler(createSecrets, "secrets").
		ReconcilerWatchByGK("secrets", SECRET)
}

func createSecrets(controller controller.Interface) (reconcile.Interface, error) {
	this := &secretReconciler{
		Common: NewCommon(controller),
		cache:  GetSharedSecrets(controller),
	}
	return this, nil
}

func (this *secretReconciler) Reconcile(logger logger.LogContext, obj resources.Object) reconcile.Status {
	users := this.cache.GetSecretUsers(obj.ObjectName())
	if len(users) > 0 {
		logger.Infof("secret %s updated -> trigger using links", obj.ObjectName())
		for n := range users {
			this.TriggerLink(n.Name())
		}
	}
	this.cache.Notify(obj.ObjectName(), obj)
	return reconcile.Succeeded(logger)
}

func (this *secretReconciler) Deleted(logger logger.LogContext, key resources.ClusterObjectKey) reconcile.Status {
	users := this.cache.GetSecretUsers(key.ObjectName())
	if len(users) > 0 {
		logger.Infof("secret %s deleted -> trigger using links", key.ObjectName())
		for n := range users {
			this.TriggerLink(n.Name())
		}
	}
	this.cache.Notify(key.ObjectName(), nil)
	return reconcile.Succeeded(logger)
}

////////////////////////////////////////////////////////////////////////////////

var secretsKey = ctxutil.SimpleKey("secrets")

func GetSharedSecrets(controller controller.Interface) *SecretCache {
	return controller.GetEnvironment().GetOrCreateSharedValue(secretsKey, func() interface{} {
		return NewSecretCache(controller.GetMainCluster())
	}).(*SecretCache)
}

type SecretCache struct {
	lock            sync.RWMutex
	resource        resources.Interface
	requiredSecrets map[resources.ObjectName]resources.ObjectNameSet
	notifications   map[resources.ObjectName]map[NotificationHandler]struct{}
}

func NewSecretCache(r resources.ResourcesSource) *SecretCache {
	resc, err := r.Resources().Get(SECRET)
	if err != nil {
		return nil
	}
	return &SecretCache{
		resource:        resc,
		requiredSecrets: map[resources.ObjectName]resources.ObjectNameSet{},
		notifications:   map[resources.ObjectName]map[NotificationHandler]struct{}{},
	}
}

func isComparable(i interface{}) bool {
	if utils.IsNil(i) {
		return false
	}
	return reflect.ValueOf(i).Type().Comparable()
}

func (this *SecretCache) AddNotificationHandler(h NotificationHandler, names ...resources.ObjectName) error {
	if !isComparable(h) {
		return fmt.Errorf("handler not hashable")
	}
	this.lock.Lock()
	defer this.lock.Unlock()
	for _, n := range names {
		m := this.notifications[n]
		if m == nil {
			m = map[NotificationHandler]struct{}{}
			this.notifications[n] = m
		}
		m[h] = struct{}{}
		obj, err := this.resource.Get(n)
		if err != nil {
			h.NotifyChange(n, nil)
		} else {
			h.NotifyChange(n, obj)
		}
	}
	return nil
}

func (this *SecretCache) RemoveNotificationHandler(h NotificationHandler, names ...resources.ObjectName) error {
	if !isComparable(h) {
		return fmt.Errorf("handler not hashable")
	}
	this.lock.Lock()
	defer this.lock.Unlock()
	for _, n := range names {
		m := this.notifications[n]
		if m != nil {
			delete(m, h)
		}
	}
	return nil
}

func (this *SecretCache) Notify(name resources.ObjectName, obj resources.Object) {
	this.lock.RLock()
	defer this.lock.RUnlock()
	for h := range this.notifications[name] {
		h.NotifyChange(name, obj)
	}
}

func (this *SecretCache) GetSecretUsers(name resources.ObjectName) resources.ObjectNameSet {
	this.lock.RLock()
	defer this.lock.RUnlock()

	set := this.requiredSecrets[name]
	if set == nil {
		return nil
	}
	return set.Copy()
}

func (this *SecretCache) UpdateSecret(name resources.ObjectName, link resources.ObjectName) {
	this.lock.Lock()
	defer this.lock.Unlock()

	for secret, old := range this.requiredSecrets {
		if old.Contains(link) {
			if resources.EqualsObjectName(name, secret) {
				return
			}
			this.cleanup(secret, old, link)
		}
	}
	set := this.requiredSecrets[name]
	if set == nil {
		set = resources.NewObjectNameSet()
		this.requiredSecrets[name] = set
	}
	set.Add(link)
}

func (this *SecretCache) AllocSecret(name resources.ObjectName, link resources.ObjectName) {
	this.lock.Lock()
	defer this.lock.Unlock()

	set := this.requiredSecrets[name]
	if set == nil {
		set = resources.NewObjectNameSet()
		this.requiredSecrets[name] = set
	}
	set.Add(link)
}

func (this *SecretCache) ReleaseSecret(name resources.ObjectName, link resources.ObjectName) {
	this.lock.Lock()
	defer this.lock.Unlock()

	this.cleanup(name, this.requiredSecrets[name], link)
}

func (this *SecretCache) ReleaseSecretForLink(link resources.ObjectName) {
	this.lock.Lock()
	defer this.lock.Unlock()

	for name, set := range this.requiredSecrets {
		this.cleanup(name, set, link)
	}
}

func (this *SecretCache) cleanup(name resources.ObjectName, set resources.ObjectNameSet, links ...resources.ObjectName) {
	if set != nil {
		for _, l := range links {
			set.Remove(l)
		}
		if len(set) == 0 {
			delete(this.requiredSecrets, name)
		}
	}
}
