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
	"net"

	"github.com/gardener/controller-manager-library/pkg/config"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/vishvananda/netlink"

	"github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/kubelink"
)

type StatusUpdater func(obj *v1alpha1.KubeLink, err error) (bool, error)

type ReconcilerImplementation interface {
	IsManagedRoute(*netlink.Route, kubelink.Routes) bool
	RequiredRoutes() kubelink.Routes
	Config(interface{}) *Config

	Gateway(obj *v1alpha1.KubeLink) (net.IP, error)
	UpdateGateway(link *v1alpha1.KubeLink) *string
}

type Common struct {
	reconcile.DefaultReconciler
	controller controller.Interface
}

func NewCommon(controller controller.Interface) Common {
	return Common{
		controller: controller,
	}
}

func (this *Common) Controller() controller.Interface {
	return this.controller
}

func (this *Common) TriggerUpdate() {
	this.controller.Infof("trigger update")
	this.Controller().EnqueueCommand(CMD_UPDATE)
}

func (this *Common) TriggerLink(name string) {
	this.Controller().EnqueueKey(resources.NewClusterKey(
		this.controller.GetMainCluster().GetId(),
		v1alpha1.KUBELINK, "", name),
	)
}

////////////////////////////////////////////////////////////////////////////////

type Reconciler struct {
	Common

	config     config.OptionSource
	baseconfig *Config

	ifce  *kubelink.NodeInterface
	links *kubelink.Links

	impl ReconcilerImplementation
}

var _ reconcile.Interface = &Reconciler{}

///////////////////////////////////////////////////////////////////////////////

func (this *Reconciler) Config() config.OptionSource {
	return this.config
}

func (this *Reconciler) NodeInterface() *kubelink.NodeInterface {
	return this.ifce
}

func (this *Reconciler) Links() *kubelink.Links {
	return this.links
}

///////////////////////////////////////////////////////////////////////////////

func (this *Reconciler) Setup() {
	this.links.Setup(this.controller, this.controller.GetMainCluster())
	this.controller.Infof("setup done")
}

func (this *Reconciler) Start() {
	this.TriggerUpdate()
}

func (this *Reconciler) Reconcile(logger logger.LogContext, obj resources.Object) reconcile.Status {
	return this.ReconcileLink(logger, obj, nil)
}

func (this *Reconciler) ReconcileLink(logger logger.LogContext, obj resources.Object,
	updater func(logger logger.LogContext, link *v1alpha1.KubeLink, entry *kubelink.Link) (error, error)) reconcile.Status {
	_, status := this.ReconcileAngGetLink(logger, obj, updater)
	return status
}

func (this *Reconciler) ReconcileAngGetLink(logger logger.LogContext, obj resources.Object,
	updater func(logger logger.LogContext, link *v1alpha1.KubeLink, entry *kubelink.Link) (error, error)) (*kubelink.Link, reconcile.Status) {
	orig := obj.Data().(*v1alpha1.KubeLink)
	link := orig
	logger.Infof("reconcile cidr %s[gateway %s]", link.Spec.CIDR, link.Status.Gateway)

	gateway, err := this.impl.Gateway(link)
	if gateway != nil {
		s := gateway.String()
		if link.Status.Gateway != s {
			link = link.DeepCopy()
			link.Status.Gateway = s
		}
	}

	var invalid error
	var ldata *kubelink.Link
	var uerr error
	if err == nil {
		ldata, invalid = this.links.UpdateLink(link)
		if updater != nil {
			uerr, err = updater(logger, link, ldata)
		}
	}
	if this.updateLink(logger, orig, err, invalid, false) {
		_, err2 := obj.ModifyStatus(func(data resources.ObjectData) (bool, error) {
			return this.updateLink(logger, data.(*v1alpha1.KubeLink), err, invalid, true), nil
		})

		if err2 != nil {
			return ldata, reconcile.Delay(logger, err2)
		}
	}
	if err != nil {
		return ldata, reconcile.Failed(logger, err)
	}
	this.TriggerUpdate()
	if uerr != nil {
		return ldata, reconcile.Delay(logger, uerr)
	}
	return ldata, reconcile.Succeeded(logger)
}

func (this *Reconciler) updateLink(logger logger.LogContext, klink *v1alpha1.KubeLink, err, invalid error, update bool) bool {

	mod := false
	msg := klink.Status.Message
	state := klink.Status.State

	gw := this.impl.UpdateGateway(klink)

	if err != nil || invalid != nil {
		if invalid != nil {
			state = v1alpha1.STATE_INVALID
			msg = invalid.Error()
		} else {
			state = v1alpha1.STATE_ERROR
			msg = err.Error()
		}
	} else {
		if gw != nil && *gw != "" {
			state = v1alpha1.STATE_UP
			msg = ""
		}
	}

	if klink.Status.State != state {
		mod = true
		if logger != nil {
			logger.Infof("update state %q -> %q", klink.Status.State, state)
		}
		if update {
			klink.Status.State = state
		}
	}
	if klink.Status.Message != msg {
		mod = true
		if logger != nil {
			logger.Infof("update message %q -> %q", klink.Status.Message, msg)
		}
		if update {
			klink.Status.Message = msg
		}
	}
	if gw != nil && klink.Status.Gateway != *gw {
		mod = true
		if logger != nil {
			logger.Infof("update gateway %q -> %q", klink.Status.Gateway, *gw)
		}
		if update {
			klink.Status.Gateway = *gw
		}
	}
	return mod
}

func (this *Reconciler) Delete(logger logger.LogContext, obj resources.Object) reconcile.Status {
	logger.Infof("delete")
	this.links.RemoveLink(obj.GetName())
	this.TriggerUpdate()
	return reconcile.Succeeded(logger)
}

func (this *Reconciler) Deleted(logger logger.LogContext, key resources.ClusterObjectKey) reconcile.Status {
	logger.Infof("deleted")
	this.links.RemoveLink(key.Name())
	this.TriggerUpdate()
	return reconcile.Succeeded(logger)
}

type notifier struct {
	logger.LogContext
	pending []string
	active  bool
}

func (this *notifier) add(print bool, msg string, args ...interface{}) {
	if print || this.active {
		if len(this.pending) > 0 {
			for _, p := range this.pending {
				this.Info(p)
			}
			this.pending = nil
		}
		this.Infof(msg, args...)
		this.active = true
	} else {
		this.pending = append(this.pending, fmt.Sprintf(msg, args...))
	}
}

func String(r netlink.Route) string {
	return fmt.Sprintf("%s proto: %d", r, r.Protocol)
}

func (this *Reconciler) Command(logger logger.LogContext, cmd string) reconcile.Status {
	logger.Info("update routes")
	routes, err := kubelink.ListRoutes()
	if err != nil {
		return reconcile.Delay(logger, err)
	}
	required := this.impl.RequiredRoutes()
	mcnt := 0
	dcnt := 0
	ocnt := 0
	ccnt := 0
	n := &notifier{LogContext: logger}
	for i, r := range routes {
		if this.impl.IsManagedRoute(&r, required) {
			mcnt++
			if required.Lookup(r) < 0 {
				dcnt++
				r.String()
				n.add(dcnt > 0, "obsolete    %3d: %s", i, String(r))
				err := netlink.RouteDel(&r)
				if err != nil {
					logger.Errorf("cannot delete route %s: %s", String(r), err)
				}
			} else {
				n.add(dcnt > 0, "keep        %3d: %s", i, String(r))
			}
		} else {
			ocnt++
			// n.add(true, "other       %d: %s", i, String(r))
		}
	}

	for i, r := range required {
		if o := routes.Lookup(r); o < 0 {
			ccnt++
			n.add(true, "missing    *%3d: %s", i, String(r))
			err := netlink.RouteAdd(&r)
			if err != nil {
				logger.Errorf("cannot add route %s: %s", String(r), err)
			}
		}
	}

	logger.Infof("found %d managed (%d deleted) and %d created routes (%d other)", mcnt, dcnt, ccnt, ocnt)

	return reconcile.Succeeded(logger)
}
