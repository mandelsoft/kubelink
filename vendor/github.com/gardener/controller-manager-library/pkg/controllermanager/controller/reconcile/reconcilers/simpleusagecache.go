/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package reconcilers

import (
	"fmt"
	"sync"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/cluster"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/ctxutil"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/gardener/controller-manager-library/pkg/resources/filter"
)

var usersKey = ctxutil.SimpleKey("users")

// GetSharedSimpleUsageCache returns an instance of a usage cache unique for
// the complete controller manager
func GetSharedSimpleUsageCache(controller controller.Interface) *SimpleUsageCache {
	return controller.GetEnvironment().GetOrCreateSharedValue(usersKey, func() interface{} {
		return NewSimpleUsageCache()
	}).(*SimpleUsageCache)
}

type SimpleUsageCache struct {
	resources.ClusterObjectKeyLocks
	lock        sync.RWMutex
	users       map[resources.ClusterObjectKey]resources.ClusterObjectKeySet
	uses        map[resources.ClusterObjectKey]resources.ClusterObjectKeySet
	reconcilers controller.WatchedResources
}

func NewSimpleUsageCache() *SimpleUsageCache {
	return &SimpleUsageCache{
		users:       map[resources.ClusterObjectKey]resources.ClusterObjectKeySet{},
		uses:        map[resources.ClusterObjectKey]resources.ClusterObjectKeySet{},
		reconcilers: controller.WatchedResources{},
	}
}

// reconcilerFor is used to assure that only one reconciler in one controller
// handles the usage reconcilations. The usage cache is hold at controller
// extension level and is shared among all controllers of a controller manager.
func (this *SimpleUsageCache) reconcilerFor(cluster cluster.Interface, gks ...schema.GroupKind) resources.GroupKindSet {
	responsible := resources.GroupKindSet{}

	this.lock.Lock()
	defer this.lock.Unlock()
	this.reconcilers.GatheredAdd(cluster.GetId(), responsible, gks...)
	return responsible
}

func (this *SimpleUsageCache) GetUsersFor(name resources.ClusterObjectKey) resources.ClusterObjectKeySet {
	this.lock.RLock()
	defer this.lock.RUnlock()

	set := this.users[name]
	if set == nil {
		return nil
	}
	return set.Copy()
}

func (this *SimpleUsageCache) GetFilteredUsersFor(name resources.ClusterObjectKey, filter resources.KeyFilter) resources.ClusterObjectKeySet {
	this.lock.RLock()
	defer this.lock.RUnlock()

	set := this.users[name]
	if set == nil {
		return nil
	}
	copy := resources.NewClusterObjectKeySet()
	for k := range set {
		if filter == nil || filter(k) {
			copy.Add(k)
		}
	}
	return copy
}

func (this *SimpleUsageCache) GetUsesFor(name resources.ClusterObjectKey) resources.ClusterObjectKeySet {
	this.lock.RLock()
	defer this.lock.RUnlock()

	set := this.uses[name]
	if set == nil {
		return nil
	}
	return set.Copy()
}

func (this *SimpleUsageCache) GetFilteredUsesFor(name resources.ClusterObjectKey, filter resources.KeyFilter) resources.ClusterObjectKeySet {
	this.lock.RLock()
	defer this.lock.RUnlock()

	set := this.uses[name]
	if set == nil {
		return nil
	}
	copy := resources.NewClusterObjectKeySet()
	for k := range set {
		if filter == nil || filter(k) {
			copy.Add(k)
		}
	}
	return copy
}

func (this *SimpleUsageCache) SetUsesFor(user resources.ClusterObjectKey, used *resources.ClusterObjectKey) {
	if used == nil {
		this.UpdateUsesFor(user, nil)
	} else {
		this.UpdateUsesFor(user, resources.NewClusterObjectKeySet(*used))
	}
}

func (this *SimpleUsageCache) UpdateUsesFor(user resources.ClusterObjectKey, uses resources.ClusterObjectKeySet) {
	this.UpdateFilteredUsesFor(user, nil, uses)
}

func (this *SimpleUsageCache) UpdateFilteredUsesFor(user resources.ClusterObjectKey, filter resources.KeyFilter, uses resources.ClusterObjectKeySet) {
	uses = uses.Filter(filter)
	this.lock.Lock()
	defer this.lock.Unlock()

	var add, del resources.ClusterObjectKeySet
	old := this.uses[user].Filter(filter)
	if old != nil {
		add, del = old.DiffFrom(uses)
		this.cleanup(user, del)
	} else {
		add = uses
	}
	if len(add) > 0 {
		for used := range uses {
			this.addUseFor(user, used)
		}
	}
}

func (this *SimpleUsageCache) AddUseFor(user resources.ClusterObjectKey, used resources.ClusterObjectKey) {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.addUseFor(user, used)
}

func (this *SimpleUsageCache) addUseFor(user resources.ClusterObjectKey, used resources.ClusterObjectKey) {
	set := this.users[used]
	if set == nil {
		set = resources.NewClusterObjectKeySet()
		this.users[used] = set
	}
	set.Add(user)

	set = this.uses[user]
	if set == nil {
		set = resources.NewClusterObjectKeySet()
		this.uses[user] = set
	}
	set.Add(used)
}

func (this *SimpleUsageCache) RemoveUseFor(user resources.ClusterObjectKey, used resources.ClusterObjectKey) {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.removeUseFor(user, used)
}

func (this *SimpleUsageCache) removeUseFor(user resources.ClusterObjectKey, used resources.ClusterObjectKey) {
	set := this.users[used]
	if set != nil {
		set.Remove(user)
		if len(set) == 0 {
			delete(this.users, used)
		}
	}

	set = this.uses[user]
	if set != nil {
		set.Remove(used)
		if len(set) == 0 {
			delete(this.uses, user)
		}
	}
}

func (this *SimpleUsageCache) cleanup(user resources.ClusterObjectKey, uses resources.ClusterObjectKeySet) {
	if len(uses) > 0 {
		for l := range uses {
			this.removeUseFor(user, l)
		}
	}
}

func (this *SimpleUsageCache) SetupFor(log logger.LogContext, resc resources.Interface, extract resources.UsedExtractor) error {
	return ProcessResource(log, "setup", resc, func(log logger.LogContext, obj resources.Object) (bool, error) {
		used := extract(obj)
		this.UpdateUsesFor(obj.ClusterKey(), used)
		return true, nil
	})
}

func (this *SimpleUsageCache) SetupFilteredFor(log logger.LogContext, resc resources.Interface, filter resources.KeyFilter, extract resources.UsedExtractor) error {
	return ProcessResource(log, "setup", resc, func(log logger.LogContext, obj resources.Object) (bool, error) {
		used := extract(obj)
		this.UpdateFilteredUsesFor(obj.ClusterKey(), filter, used)
		return true, nil
	})
}

func (this *SimpleUsageCache) SetupForRelation(log logger.LogContext, c cluster.Interface, from, to schema.GroupKind, extractor resources.UsedExtractor) error {
	res, err := c.GetResource(from)
	if err == nil {
		err = this.SetupFilteredFor(log, res, filter.GroupKindFilter(to), extractor)
	}
	return err
}

func (this *SimpleUsageCache) CleanupUser(log logger.LogContext, msg string, controller controller.Interface, user resources.ClusterObjectKey, actions ...KeyAction) error {
	used := this.GetUsesFor(user)
	if len(actions) > 0 {
		if len(used) > 0 && log != nil && msg != "" {
			log.Infof("%s %d uses of %s", msg, len(used), user.ObjectKey())
		}
		if err := this.execute(log, controller, used, actions...); err != nil {
			return err
		}
	}
	this.UpdateUsesFor(user, nil)
	return nil
}

func (this *SimpleUsageCache) ExecuteActionForUsersOf(log logger.LogContext, msg string, controller controller.Interface, used resources.ClusterObjectKey, actions ...KeyAction) error {
	return this.ExecuteActionForFilteredUsersOf(log, msg, controller, used, nil, actions...)
}

func (this *SimpleUsageCache) ExecuteActionForFilteredUsersOf(log logger.LogContext, msg string, controller controller.Interface, key resources.ClusterObjectKey, filter resources.KeyFilter, actions ...KeyAction) error {
	if len(actions) > 0 {
		users := this.GetFilteredUsersFor(key, filter)
		if len(users) > 0 && log != nil && msg != "" {
			log.Infof("%s %d users of %s", msg, len(users), key.ObjectKey())
		}
		return this.execute(log, controller, users, actions...)
	}
	return nil
}

func (this *SimpleUsageCache) ExecuteActionForUsesOf(log logger.LogContext, msg string, controller controller.Interface, key resources.ClusterObjectKey, actions ...KeyAction) error {
	return this.ExecuteActionForFilteredUsesOf(log, msg, controller, key, nil, actions...)
}

func (this *SimpleUsageCache) ExecuteActionForFilteredUsesOf(log logger.LogContext, msg string, controller controller.Interface, key resources.ClusterObjectKey, filter resources.KeyFilter, actions ...KeyAction) error {
	if len(actions) > 0 {
		used := this.GetFilteredUsesFor(key, filter)
		if len(used) > 0 && log != nil && msg != "" {
			log.Infof("%s %d uses of %s", msg, len(used), key.ObjectKey())
		}
		return this.execute(log, controller, used, actions...)
	}
	return nil
}

func (this *SimpleUsageCache) execute(log logger.LogContext, controller controller.Interface, keys resources.ClusterObjectKeySet, actions ...KeyAction) error {
	for key := range keys {
		for _, a := range actions {
			err := a(log, controller, key)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

////////////////////////////////////////////////////////////////////////////////

type KeyAction func(log logger.LogContext, c controller.Interface, key resources.ClusterObjectKey) error

func EnqueueAction(log logger.LogContext, c controller.Interface, key resources.ClusterObjectKey) error {
	return c.EnqueueKey(key)
}

func GlobalEnqueueAction(log logger.LogContext, c controller.Interface, key resources.ClusterObjectKey) error {
	c.GetEnvironment().EnqueueKey(key)
	return nil
}

type ObjectAction func(log logger.LogContext, controller controller.Interface, obj resources.Object) error

func ObjectAsKeyAction(actions ...ObjectAction) KeyAction {
	return func(log logger.LogContext, controller controller.Interface, key resources.ClusterObjectKey) error {
		if len(actions) > 0 {
			obj, err := controller.GetClusterById(key.Cluster()).Resources().GetCachedObject(key.ObjectKey())
			if err != nil {
				if !errors.IsNotFound(err) {
					return err
				}
			} else {
				for _, a := range actions {
					err := a(log, controller, obj)
					if err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
}

func RemoveFinalizerObjectAction(log logger.LogContext, controller controller.Interface, obj resources.Object) error {
	return controller.RemoveFinalizer(obj)
}

func RemoveFinalizerAction() KeyAction {
	return ObjectAsKeyAction(RemoveFinalizerObjectAction)
}

////////////////////////////////////////////////////////////////////////////////

type usageReconciler struct {
	ReconcilerSupport
	cache       *SimpleUsageCache
	clusterId   string
	responsible resources.GroupKindSet
	relation    *UsageRelation
}

var _ reconcile.Interface = &usageReconciler{}
var _ reconcile.ReconcilationRejection = &usageReconciler{}

func (this *usageReconciler) RejectResourceReconcilation(cluster cluster.Interface, gk schema.GroupKind) bool {
	if cluster == nil || this.clusterId != cluster.GetId() {
		return true
	}
	return !this.responsible.Contains(gk)
}

func (this *usageReconciler) Setup() error {
	if this.relation != nil {
		c := this.Controller().GetCluster(this.relation.FromCluster)
		for _, r := range this.relation.To {
			this.Controller().Infof("setting up usages of %q for %q", this.relation.From, r.Resource)
			err := this.cache.SetupForRelation(this.Controller(), c, this.relation.From, r.Resource, r.Extractor)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (this *usageReconciler) Reconcile(logger logger.LogContext, obj resources.Object) reconcile.Status {
	this.cache.ExecuteActionForUsersOf(logger, "changed -> trigger", this.controller, obj.ClusterKey(), GlobalEnqueueAction)
	return reconcile.Succeeded(logger)
}

func (this *usageReconciler) Deleted(logger logger.LogContext, key resources.ClusterObjectKey) reconcile.Status {
	this.cache.ExecuteActionForUsersOf(logger, "deleted -> trigger", this.controller, key, GlobalEnqueueAction)
	return reconcile.Succeeded(logger)
}

////////////////////////////////////////////////////////////////////////////////

func UsageReconcilerForGKs(name string, cluster string, gks ...schema.GroupKind) controller.ConfigurationModifier {
	return func(c controller.Configuration) controller.Configuration {
		if c.Definition().Reconcilers()[name] == nil {
			c = c.Reconciler(CreateSimpleUsageReconcilerTypeFor(cluster, gks...), name)
		}
		return c.Cluster(cluster).ReconcilerWatchesByGK(name, gks...)
	}
}

func CreateSimpleUsageReconcilerTypeFor(clusterName string, gks ...schema.GroupKind) controller.ReconcilerType {
	return func(controller controller.Interface) (reconcile.Interface, error) {
		cache := GetSharedSimpleUsageCache(controller)
		cluster := controller.GetCluster(clusterName)
		if cluster == nil {
			return nil, fmt.Errorf("cluster %s not found", clusterName)
		}
		this := &usageReconciler{
			ReconcilerSupport: NewReconcilerSupport(controller),
			cache:             cache,
			clusterId:         cluster.GetId(),
			responsible:       cache.reconcilerFor(cluster, gks...),
		}
		return this, nil
	}
}

////////////////////////////////////////////////////////////////////////////////

type UsedResourceSpec struct {
	Resource  schema.GroupKind        // used resource
	Extractor resources.UsedExtractor // extractor for using resource
}

func UsedResource(gk schema.GroupKind, extractor resources.UsedExtractor) UsedResourceSpec {
	return UsedResourceSpec{gk, extractor}
}

type UsageRelation struct {
	FromCluster string             // cluster for From Resource
	From        schema.GroupKind   // using Resource
	ToCluster   string             // cluster for To Resource
	To          []UsedResourceSpec // used resources
}

func UsageRelationFor(fromCluster string, gk schema.GroupKind, toCluster string, specs ...UsedResourceSpec) *UsageRelation {
	return &UsageRelation{
		FromCluster: fromCluster,
		From:        gk,
		ToCluster:   toCluster,
		To:          specs,
	}
}

func UsageRelationForGK(fromCluster string, gk schema.GroupKind, toCluster string, used schema.GroupKind, extractor resources.UsedExtractor) *UsageRelation {
	return UsageRelationFor(fromCluster, gk, toCluster, UsedResource(used, extractor))
}

func MainClusterUsageRelationFor(gk schema.GroupKind, specs ...UsedResourceSpec) *UsageRelation {
	return UsageRelationFor(controller.CLUSTER_MAIN, gk, controller.CLUSTER_MAIN, specs...)
}

func MainClusterUsageRelationForGK(gk schema.GroupKind, used schema.GroupKind, extractor resources.UsedExtractor) *UsageRelation {
	return UsageRelationFor(controller.CLUSTER_MAIN, gk, controller.CLUSTER_MAIN, UsedResource(used, extractor))
}

func (this *UsageRelation) GKs() []schema.GroupKind {
	gks := []schema.GroupKind{}
	for _, r := range this.To {
		gks = append(gks, r.Resource)
	}
	return gks
}

func UsageReconcilerForRelation(name string, relation *UsageRelation) controller.ConfigurationModifier {
	return func(c controller.Configuration) controller.Configuration {
		if c.Definition().Reconcilers()[name] == nil {
			c = c.Reconciler(CreateSimpleUsageReconcilerTypeForRelation(relation), name)
		}
		return c.Cluster(relation.FromCluster).ReconcilerWatchesByGK(name, relation.GKs()...)
	}
}

func CreateSimpleUsageReconcilerTypeForRelation(relation *UsageRelation) controller.ReconcilerType {
	return func(controller controller.Interface) (reconcile.Interface, error) {
		cache := GetSharedSimpleUsageCache(controller)
		cluster := controller.GetCluster(relation.ToCluster)
		if cluster == nil {
			return nil, fmt.Errorf("cluster %s not found", relation.ToCluster)
		}
		this := &usageReconciler{
			ReconcilerSupport: NewReconcilerSupport(controller),
			cache:             cache,
			clusterId:         cluster.GetId(),
			responsible:       cache.reconcilerFor(cluster, relation.GKs()...),
			relation:          relation,
		}
		return this, nil
	}
}

////////////////////////////////////////////////////////////////////////////////

type ProcessingFunction func(logger logger.LogContext, obj resources.Object) (bool, error)

func ProcessResource(logger logger.LogContext, action string, resc resources.Interface, process ProcessingFunction) error {
	if logger != nil {
		logger.Infof("%s %s", action, resc.Name())
	}
	list, err := resc.ListCached(labels.Everything())
	if err == nil {
		for _, l := range list {
			handled, err := process(logger, l)
			if err != nil {
				logger.Infof("  errorneous %s %s: %s", resc.Name(), l.ObjectName(), err)
				if !handled {
					return err
				}
			} else {
				if handled {
					logger.Infof("  found %s %s", resc.Name(), l.ObjectName())
				}
			}
		}
	}
	return err
}
