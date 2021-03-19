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

package broker

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gardener/controller-manager-library/pkg/config"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/vishvananda/netlink"
	_apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"

	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/controllers"
	ctrlcfg "github.com/mandelsoft/kubelink/pkg/controllers/broker/config"
	"github.com/mandelsoft/kubelink/pkg/controllers/broker/runmode"
	"github.com/mandelsoft/kubelink/pkg/iptables"
	"github.com/mandelsoft/kubelink/pkg/kubelink"
	"github.com/mandelsoft/kubelink/pkg/tasks"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

type reconciler struct {
	*controllers.Reconciler
	config *ctrlcfg.Config

	runmode runmode.RunMode

	tasks tasks.Tasks

	linkResource       resources.Interface
	saResource         resources.Interface
	secretResource     resources.Interface
	deploymentResource resources.Interface
	secrets            *controllers.SecretCache

	access  kubelink.LinkAccessInfo
	dnsInfo kubelink.LinkDNSInfo

	lock            sync.RWMutex
	requiredSecrets map[resources.ObjectName]resources.ObjectNameSet
}

var _ reconcile.Interface = &reconciler{}
var _ controllers.ReconcilerImplementation = &reconciler{}

///////////////////////////////////////////////////////////////////////////////

func (this *reconciler) BaseConfig(cfg config.OptionSource) *controllers.Config {
	return &cfg.(*ctrlcfg.Config).Config
}

func (this *reconciler) Gateway(obj *api.KubeLink) (*controllers.LocalGatewayInfo, error) {
	gateway := this.NodeInterface().IP
	match, ip := this.MatchLink(obj)
	if !match {
		return nil, nil
	}
	info := &controllers.LocalGatewayInfo{Gateway: gateway}
	this.runmode.UpdateLocalGatewayInfo(info)
	return info, this.runmode.GetErrorForMeshNode(ip)
}

func (this *reconciler) GetLinkInfo(link *api.KubeLink) *controllers.LinkInfo {
	gateway := this.NodeInterface().IP
	match, _ := this.MatchLink(link)
	if !match {
		gateway = nil
	}

	var state runmode.LinkState
	if link.Spec.Endpoint != kubelink.EP_LOCAL {
		state = this.runmode.GetLinkState(link)
	} else {
		state.State = api.STATE_UP
	}
	return &controllers.LinkInfo{
		Gateway: gateway,
		State:   state.State,
		Message: state.Message,
	}
}

func (this *reconciler) IsManagedRoute(route *netlink.Route, routes kubelink.Routes) bool {
	link := this.runmode.GetInterface()

	if link != nil && route.LinkIndex == link.Attrs().Index {
		return true
	}
	if route.Dst != nil {
		for _, r := range routes {
			if tcp.EqualCIDR(route.Dst, r.Dst) {
				return true
			}
		}
	}
	return false
}

func (this *reconciler) RequiredRoutes() kubelink.Routes {
	link := this.runmode.GetInterface()
	if link == nil {
		return nil
	}
	return this.Links().GetRoutesToLink(this.NodeInterface(), link)
}

func (this *reconciler) ConfirmManagedRoutes(list tcp.CIDRList) {
}

func (this *reconciler) RequiredIPTablesChains() iptables.Requests {
	return this.runmode.RequiredIPTablesChains()
}

func (this *reconciler) HandleDelete(logger logger.LogContext, name kubelink.LinkName, obj resources.Object) (bool, error) {
	if obj != nil {
		this.secrets.ReleaseSecretForLink(controllers.ObjectName(name))
	}
	deleted := false
	err := this.Links().Locked(func(links kubelink.Links) error {
		if m := links.GetMeshByLinkName(name); m != nil {
			// link is mesh LocalLink, check if unused or existence of an appropriate replacement
			members := links.GetMeshMembersFor(m.Name())
			var replacement *kubelink.LinkName
			if len(members) != 0 {
				logger.Infof("looking for pending stale local links for mesh %q", m.Name())
				for {
					if replacement = this.Links().GetStaleMesh(m.Name()); replacement != nil {
						r, err := this.linkResource.GetCached(controllers.ObjectName(*replacement))
						if err == nil {
							logger.Infof("trying %q", *replacement)
							err = this.Controller().SetFinalizer(r)
						}
						if err != nil {
							if errors.IsNotFound(err) {
								this.Links().RemoveLink(*replacement)
								continue // try next stale mesh
							}
							return err
						}
					}
					break
				}
				if replacement != nil {
					logger.Infof("found replacement %q", *replacement)
				}
			}

			if obj != nil {
				// mesh local link can be deleted if it has no members or a replacement
				finalizers := obj.GetFinalizers()
				if len(members) == 0 || replacement != nil {
					finalizer := this.Controller().FinalizerHandler().FinalizerName(obj)
					if len(finalizers) == 1 && finalizers[0] == finalizer {
						err := this.Controller().RemoveFinalizer(obj)
						if err == nil {
							deleted = true
							logger.Infof("removing mesh %s", name)
							links.RemoveLink(name)
							if replacement != nil {
								this.TriggerLink(*replacement)
							}
						}
						return err
					}
				}
				if len(members) != 0 {
					logger.Infof("mesh still busy")
				} else {
					logger.Infof("mesh still has finalizers: %s", finalizers)
				}
			}
		} else {
			// any other links including stale mesh links can potentially just be deleted
			if obj != nil {
				// first try to remove pending finalizer
				err := this.Controller().RemoveFinalizer(obj)
				if err != nil {
					return err
				}
			}
			if obj == nil || len(obj.GetFinalizers()) == 0 {
				deleted = true
				logger.Infof("removing link %s", name)
				links.RemoveLink(name)
				if m := links.GetMesh(name.Mesh()); m != nil && m.DeletePending() {
					if n := len(links.GetMeshMembersFor(m.Name())); n == 0 {
						logger.Infof("deleting last member of mesh %s", m.Name)
						this.TriggerLink(m.LinkName())
					} else {
						logger.Infof("still %d members in deleting mesh %s", n, m.Name)
					}
				}
			} else {
				logger.Infof("still has finalizers %v", obj.GetFinalizers())
			}
		}
		return nil
	})
	return deleted && err == nil, err
}

///////////////////////////////////////////////////////////////////////////////

func (this *reconciler) MatchLink(obj *api.KubeLink) (bool, net.IP) {
	ip, cidr, err := net.ParseCIDR(obj.Spec.ClusterAddress)
	if err != nil {
		return false, nil
	}
	if !this.config.Responsible.Contains("all") && !this.config.Responsible.Contains(cidr.String()) {
		return false, nil
	}
	for _, m := range this.Links().GetMeshInfos() {
		if m.CIDR().Contains(ip) {
			return true, ip
		}
	}
	return false, ip
}

///////////////////////////////////////////////////////////////////////////////

func (this *reconciler) Config() *ctrlcfg.Config {
	return this.config
}

func (this *reconciler) Secrets() *controllers.SecretCache {
	return this.secrets
}

func (this *reconciler) Tasks() tasks.Tasks {
	return this.tasks
}

func (this *reconciler) GetAccess() kubelink.LinkAccessInfo {
	return this.access
}

func (this *reconciler) GetDNSInfo() kubelink.LinkDNSInfo {
	return this.dnsInfo
}

func (this *reconciler) Setup() error {
	this.Reconciler.Setup()

	if this.config.Mode == ctrlcfg.RUN_MODE_NONE {
		return nil
	}

	if this.config.IPIP != controllers.IPIP_NONE {
		this.WaitIPIP()
	}

	return this.runmode.Setup()
}

func (this *reconciler) Cleanup() error {
	if this.runmode != nil {
		return this.runmode.Cleanup()
	}
	return nil
}

func (this *reconciler) Start() {
	this.runmode.Start()
	if this.config.CoreDNSConfigure {
		this.ConnectCoredns()
	}
	this.Reconciler.Start()
}

func (this *reconciler) Command(logger logger.LogContext, cmd string) reconcile.Status {
	err := this.runmode.ReconcileInterface(logger)
	if err != nil {
		this.Controller().Errorf("wireguard reconcilation failed: %s", err)
	}
	if this.config.ServiceAccount != nil {
		logger.Debug("update service account")
		access, err := this.getServiceAccountToken()
		if err != nil {
			logger.Errorf("cannot get service account token: %s", err)
		}
		if access != nil {
			this.access = *access
		} else {
			this.access = kubelink.LinkAccessInfo{}
		}
	}
	if this.config.DNSPropagation != kubelink.DNSMODE_NONE {
		this.updateCorefile(logger)
		this.ConnectCoredns()
	}
	return this.Reconciler.Command(logger, cmd)
}

func (this *reconciler) getServiceAccountToken() (*kubelink.LinkAccessInfo, error) {
	if this.config.ServiceAccount == nil {
		return nil, fmt.Errorf("no service accound specified")
	}
	sa := core.ServiceAccount{}
	_, err := this.saResource.GetInto(this.config.ServiceAccount, &sa)
	if err != nil {
		return nil, err
	}
	for _, s := range sa.Secrets {
		ns := s.Namespace
		if ns == "" {
			ns = sa.Namespace
		}
		name := resources.NewObjectName(ns, s.Name)
		obj, err := this.secretResource.GetCached(name)
		if err != nil {
			return nil, err
		}
		secret := obj.Data().(*core.Secret)
		cacert := getStringValue("ca.crt", secret)
		token := getStringValue("token", secret)
		return &kubelink.LinkAccessInfo{Token: token, CACert: cacert}, nil
	}
	return nil, nil
}

func (this *reconciler) RestartDeployment(logger logger.LogContext, name resources.ObjectDataName) error {
	if logger == nil {
		logger = this.Controller()
	}
	_, _, err := this.deploymentResource.ModifyByName(name,
		func(odata resources.ObjectData) (bool, error) {
			depl := odata.(*_apps.Deployment)
			annos := depl.Spec.Template.Annotations
			if annos == nil {
				annos = map[string]string{}
				depl.Spec.Template.Annotations = annos
			}
			annos["kubelink.mandelsoft.org/restartedAt"] = time.Now().String()
			return true, nil
		})
	if err != nil {
		logger.Errorf("cannot restart deployment %q: %s", name, err)
	} else {
		logger.Infof("deployment %q restarted", name)
	}
	return err
}

func (this *reconciler) UpdateLinkInfo(logger logger.LogContext, name kubelink.LinkName, access *kubelink.LinkAccessInfo, dns *kubelink.LinkDNSInfo) {
	_, err := this.linkResource.GetCached(controllers.ObjectName(name))
	if err != nil {
		logger.Infof("cannot get link %s: %s", name, err)
		return
	}
	_, mod := this.Links().UpdateLinkInfo(logger, name, access, dns, true)
	if mod {
		logger.Infof("link access for %s modified -> trigger link", name)
		this.TriggerUpdate()
		this.TriggerLink(name)
	}
}

func (this *reconciler) HandleReconcile(logger logger.LogContext, obj resources.Object, entry *kubelink.Link) (error, error) {
	klink := obj.Data().(*api.KubeLink)
	if entry != nil {
		if this.dnsInfo.DNSPropagation && entry.DNSPropagation {
			this.runmode.HandleDNSPropagation(klink)
		}
		logger.Infof("link %s", entry)
		if entry.IsLocalLink() && this.Links().GetMeshByLinkName(entry.Name) != nil {
			if entry.ServiceCIDR == nil && this.config.ServiceCIDR != nil {
				if !tcp.EqualCIDR(this.config.ServiceCIDR, entry.ServiceCIDR) {
					entry.ServiceCIDR = this.config.ServiceCIDR
					entry.UpdatePending = true
				}
			}
			err := this.Controller().SetFinalizer(obj)
			if err != nil {
				return err, nil
			}
		} else {
			err := this.Controller().RemoveFinalizer(obj)
			if err != nil {
				return err, nil
			}
		}
	}

	if entry.UpdatePending {
		return this.updateObjectFromLink(logger, klink, entry)
	} else {
		return this.updateLinkFromObject(logger, klink, entry)
	}
}

func getStringValue(key string, secret *core.Secret) string {
	bytes := secret.Data[key]
	if bytes == nil {
		return ""
	}
	return string(bytes)
}
