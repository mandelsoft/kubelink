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
	"syscall"
	"time"

	"github.com/gardener/controller-manager-library/pkg/config"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/gardener/controller-manager-library/pkg/utils"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/iptables"
	"github.com/mandelsoft/kubelink/pkg/kubelink"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

func init() {
	if api.EP_INBOUND != kubelink.EP_INBOUND {
		panic("EP_INBOUND constant mismatch")
	}
}

type StatusUpdater func(obj *api.KubeLink, err error) (bool, error)

type LocalGatewayInfo struct {
	Gateway   net.IP
	PublicKey string
}

type ReconcilerImplementation interface {
	IsManagedRoute(*netlink.Route, kubelink.Routes) bool
	RequiredRoutes() kubelink.Routes
	RequiredIPTablesChains() iptables.Requests
	BaseConfig(config.OptionSource) *Config

	Gateway(obj *api.KubeLink) (*LocalGatewayInfo, error)
	UpdateGateway(link *api.KubeLink) *string
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

func (this *Common) TriggerLink(name kubelink.LinkName) {
	this.controller.Infof("trigger link %s", name)
	n := name.Name()
	if name.Mesh() != kubelink.DEFAULT_MESH {
		n = name.String()
	}
	this.Controller().EnqueueKey(resources.NewClusterKey(
		this.controller.GetMainCluster().GetId(),
		api.KUBELINK, "", n),
	)
}

////////////////////////////////////////////////////////////////////////////////

type Reconciler struct {
	Common
	tool *LinkTool

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

func (this *Reconciler) LinkTool() *LinkTool {
	return this.tool
}

func (this *Reconciler) NodeInterface() *kubelink.NodeInterface {
	return this.ifce
}

func (this *Reconciler) Links() *kubelink.Links {
	return this.links
}

///////////////////////////////////////////////////////////////////////////////

func (this *Reconciler) Setup() {
	res, _ := this.controller.GetMainCluster().Resources().Get(api.KUBELINK)
	list, _ := res.ListCached(labels.Everything())

	this.links.Setup(this.controller, list)
	this.controller.Infof("setup done")
}

func (this *Reconciler) Start() {
	this.TriggerUpdate()
}

func (this *Reconciler) Reconcile(logger logger.LogContext, obj resources.Object) reconcile.Status {
	if obj.GroupKind() == api.KUBELINK {
		return this.ReconcileLink(logger, obj, nil)
	}
	return reconcile.Failed(logger, fmt.Errorf("unknown object type %q", obj.GroupKind()))
}

func (this *Reconciler) ReconcileLink(logger logger.LogContext, obj resources.Object,
	updater func(logger logger.LogContext, link *api.KubeLink, entry *kubelink.Link) (error, error)) reconcile.Status {
	_, status := this.ReconcileAndGetLink(logger, obj, updater)
	return status
}

func (this *Reconciler) ReconcileAndGetLink(logger logger.LogContext, obj resources.Object,
	updater func(logger logger.LogContext, link *api.KubeLink, entry *kubelink.Link) (error, error)) (*kubelink.Link, reconcile.Status) {
	orig := obj.Data().(*api.KubeLink)
	link := orig
	logger.Infof("reconcile cidr %s[gateway %s]", link.Spec.CIDR, link.Status.Gateway)

	gateway, err := this.impl.Gateway(link)
	if gateway != nil {
		s := gateway.Gateway.String()
		if link.Status.Gateway != s || (link.Spec.Endpoint == kubelink.EP_LOCAL && link.Status.PublicKey != gateway.PublicKey) {
			link = link.DeepCopy()
			link.Status.Gateway = s
			if link.Spec.Endpoint == kubelink.EP_LOCAL {
				link.Status.PublicKey = gateway.PublicKey
			}
		}
	}
	state := link.Status.State
	if err != nil {
		logger.Infof("  link error: %s", err)
		state = api.STATE_ERROR
	}

	var ldata *kubelink.Link
	var uerr error
	if err == nil {
		var valid bool
		ldata, valid, err = this.links.UpdateLink(link)
		if err != nil {
			if valid {
				logger.Warnf("invalid link: %s", err)
				state = api.STATE_INVALID
			} else {
				logger.Warnf("stale link: %s", err)
				state = api.STATE_STALE
			}
		} else {
			if ldata != nil {
				if len(ldata.GatewayFor) != 0 {
					logger.Info("used as gateway for %s", ldata.GatewayFor)
				}
				if ldata.GatewayLink != nil {
					logger.Info("using gateway link %s", ldata.GatewayLink)
				}
				if updater != nil {
					uerr, err = updater(logger, link, ldata)
				}
				// reconcile all using objects
				served := this.Links().ServedLinksFor(ldata.Name)
				if len(served) > 0 {
					logger.Infof("triggering served links")
					for u := range served {
						this.TriggerLink(u)
					}
				}
				if ldata.IsLocalLink() {
					logger.Infof("triggering mesh members")
					for u := range this.Links().MeshLinksFor(ldata.Name.Mesh()) {
						this.TriggerLink(u)
					}
				}
			}
		}
	}
	if this.updateLink(logger, orig, state, err, false) {
		_, err2 := obj.ModifyStatus(func(data resources.ObjectData) (bool, error) {
			return this.updateLink(logger, data.(*api.KubeLink), state, err, true), nil
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

func (this *Reconciler) updateLink(logger logger.LogContext, klink *api.KubeLink, state string, err error, update bool) bool {

	mod := false
	msg := klink.Status.Message
	gw := this.impl.UpdateGateway(klink)

	if err != nil {
		msg = err.Error()
	} else {
		if gw != nil && *gw != "" {
			if state != api.STATE_ERROR {
				state = api.STATE_UP
				msg = ""
			}
		} else {
			state = api.STATE_STALE
			msg = "no gateway"
		}
	}

	if klink.Status.State != state {
		mod = true
		if update {
			if logger != nil {
				logger.Infof("update state %q -> %q", klink.Status.State, state)
			}
			klink.Status.State = state
		}
	}
	if klink.Status.Message != msg {
		mod = true
		if update {
			if logger != nil {
				logger.Infof("update message %q -> %q", klink.Status.Message, msg)
			}
			klink.Status.Message = msg
		}
	}
	if gw != nil && klink.Status.Gateway != *gw {
		mod = true
		if update {
			if logger != nil {
				logger.Infof("update gateway %s -> %s", klink.Status.Gateway, *gw)
			}
			klink.Status.Gateway = *gw
		}
	}
	return mod
}

func (this *Reconciler) Delete(logger logger.LogContext, obj resources.Object) reconcile.Status {
	if obj.GroupKind() == api.KUBELINK {
		logger.Infof("delete")
		this.links.RemoveLink(kubelink.DecodeLinkNameFromString(obj.GetName()))
		this.TriggerUpdate()
		return reconcile.Succeeded(logger)
	}
	return reconcile.Failed(logger, fmt.Errorf("unknown object type %q", obj.GroupKind()))
}

func (this *Reconciler) Deleted(logger logger.LogContext, key resources.ClusterObjectKey) reconcile.Status {
	if key.GroupKind() == api.KUBELINK {
		logger.Infof("deleted")
		this.links.RemoveLink(kubelink.DecodeLinkNameFromString(key.Name()))
		this.TriggerUpdate()
		return reconcile.Succeeded(logger)
	}
	return reconcile.Failed(logger, fmt.Errorf("unknown object type %q", key.GroupKind()))
}

func String(r netlink.Route) string {
	return fmt.Sprintf("%s proto: %d", r, r.Protocol)
}

func (this *Reconciler) updateFirewall(logger logger.LogContext) error {
	reqs := this.impl.RequiredIPTablesChains()

	if reqs == nil {
		return nil
	}
	logger.Debug("update firewall")
	return this.LinkTool().HandleFirewall(logger, reqs)
}

func (this *Reconciler) Command(logger logger.LogContext, cmd string) reconcile.Status {
	err := this.updateFirewall(logger)
	if err != nil {
		logger.Errorf("cannot update iptables rules: %s", err)
	}
	routes, err := kubelink.ListRoutes()
	if err != nil {
		return reconcile.Delay(logger, err)
	}
	required := this.impl.RequiredRoutes()
	mcnt := 0
	dcnt := 0
	ocnt := 0
	ccnt := 0
	n := utils.NewNotifier(logger, "update routes")
	for i, r := range routes {
		if this.impl.IsManagedRoute(&r, required) {
			mcnt++
			if required.Lookup(r) < 0 {
				dcnt++
				r.String()
				n.Add(dcnt > 0, "obsolete    %3d: %s", i, String(r))
				err := netlink.RouteDel(&r)
				if err != nil {
					logger.Errorf("cannot delete route %s: %s", String(r), err)
				}
			} else {
				n.Add(dcnt > 0, "keep        %3d: %s", i, String(r))
			}
		} else {
			ocnt++
			// n.add(true, "other       %d: %s", i, String(r))
		}
	}

	for i, r := range required {
		if o := routes.Lookup(r); o < 0 {
			ccnt++
			n.Add(true, "missing    *%3d: %s", i, String(r))
			err := netlink.RouteAdd(&r)
			if err != nil {
				logger.Errorf("cannot add route %s: %s", String(r), err)
			}
		}
	}

	n.Add(false, "found %d managed (%d deleted) and %d created routes (%d other)", mcnt, dcnt, ccnt, ocnt)

	wg, err := wgctrl.New()
	if err == nil {
		defer wg.Close()
		devs, err := wg.Devices()
		if err == nil {
			n := utils.NewNotifier(logger, fmt.Sprintf("found %d wireguard device(s)", len(devs)))
			for _, d := range devs {
				match := false
				link, err := netlink.LinkByName(d.Name)
				if err != nil {
					n.Errorf("link %s not found: %s", d.Name, err)
					continue
				}
				addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
				if err != nil {
					n.Errorf("cannot get address list for link %s: %s", d.Name, err)
					continue
				}
				for _, a := range addrs {
					gateways := this.Links().LookupMeshGatewaysFor(a.IP)
					if gateways.Contains(this.ifce.IP) {
						match = true
						break
					}
					if len(gateways) != 0 {
						n.Debugf("  gateways %s for cluster address %s does not match node ip %s", gateways, a.IP, this.ifce.IP)
					} else {
						n.Debugf("  no kubelink found for link address %s", a.IP)
					}
				}
				if !match {
					n.Infof("  garbage collecting unused wireguard interface %q", link.Attrs().Name)
					netlink.LinkDel(link)
				}
			}
		}
	}
	return reconcile.Succeeded(logger)
}

func (this *Reconciler) WaitIPIP() {
	msg := ""
	d := 10 * time.Second
	for {
		l, err := netlink.LinkByName("tunl0")
		if err != nil {
			this.Controller().Errorf("error getting tunl0 interface: %s", err)
			return
		}
		if link, ok := l.(*netlink.Iptun); ok {
			attrs := link.Attrs()
			msg = "waiting for tunl0 to be up"
			if attrs.Flags&net.FlagUp != 0 {
				this.Controller().Infof("tunl0 is up")
				addrs, _ := netlink.AddrList(link, netlink.FAMILY_V4)
				if err != nil {
					this.Controller().Errorf("error getting tunl0 addresses: %s", err)
					return
				}
				for _, addr := range addrs {
					this.Controller().Infof("  found address %s", addr.IP)
				}
				if len(addrs) > 0 {
					return
				}
				msg = "waiting for tunl0 to get IPv4 address"

			}
		}
		this.Controller().Infof("%s", msg)
		time.Sleep(d)
		d = time.Duration(1.1 * float64(d))
	}
}

func (this *Reconciler) SetupIPIP() error {
	link := &netlink.Iptun{LinkAttrs: netlink.LinkAttrs{Name: "tunl0"}}
	err := netlink.LinkAdd(link)
	if err != nil && err != syscall.EEXIST {
		return fmt.Errorf("error creating tunl0 interface: %s", err)
	} else {
		if err == nil {
			this.Controller().Infof("created interface tunl0[%d] for ip-over-ip routing option", link.Attrs().Index)
		} else {
			this.Controller().Infof("found interface tunl0[%d] for ip-over-ip routing option", link.Attrs().Index)
		}

		l, err := netlink.LinkByName("tunl0")
		if err != nil {
			return fmt.Errorf("error getting tunl0 interface: %s", err)
		} else {
			if link, ok := l.(*netlink.Iptun); ok {
				attrs := link.Attrs()
				mtu := 1440
				if attrs.MTU != mtu {
					err = netlink.LinkSetMTU(link, mtu)
					if err != nil {
						this.Controller().Errorf("cannot set MTU for tunl0: %s", err)
					} else {
						this.Controller().Errorf("setting MTU for tunl0: %d", mtu)
					}
				}
				if attrs.Flags&net.FlagUp == 0 {
					err = netlink.LinkSetUp(link)
					if err != nil {
						return fmt.Errorf("cannot bring up tunl0: %s", err)
					} else {
						this.Controller().Infof("bring up tunl0")
					}
				}
				ip := this.ifce.IP
				addr := &netlink.Addr{
					IPNet: &net.IPNet{
						IP:   ip,
						Mask: net.CIDRMask(len(ip)*8, len(ip)*8),
					},
				}
				addrs, err := netlink.AddrList(link, tcp.Family(ip))
				found := false
				for _, oldAddr := range addrs {
					found = true
					if oldAddr.IP.Equal(addr.IP) {
						this.Controller().Infof("tunl0 address %s already present", oldAddr)
						continue
					} else {
						this.Controller().Infof("tunl0 address found: %s", oldAddr)
					}
				}

				if !found {
					logger.Infof("adding address %s to tunl0", addr.String())
					err = netlink.AddrAdd(link, addr)
					if err != nil {
						return fmt.Errorf("cannot add addr %q to tunl0: %s", addr, err)
					}
				}
			} else {
				return fmt.Errorf("tunl0 isn't an iptun device (%#v), please remove device and try again", l)
			}
		}
	}
	return nil
}

func (this *Reconciler) WaitNetworkReady() {
	resc, err := this.Controller().GetMainCluster().GetResource(resources.NewGroupKind(core.GroupName, "Node"))
	if err != nil {
		panic(err)
	}
	nodeIP := this.NodeInterface().IP.String()
	this.Controller().Infof("lookup node for ip %s...", nodeIP)
	var node *core.Node
	for node == nil {
		nodes, err := resc.List(meta.ListOptions{})
		if err != nil {
			this.Controller().Infof("cannot list nodes: %s", err)
		} else {
			for _, n := range nodes {
				tmp := n.Data().(*core.Node)
				for _, a := range tmp.Status.Addresses {
					if a.Type == "InternalIP" {
						if a.Address == nodeIP {
							node = tmp
							break
						}
					}
				}
			}
		}
		if node == nil {
			this.Controller().Infof("no node found for node IP %s", nodeIP)
			time.Sleep(10 * time.Second)
		}
	}

	this.Controller().Infof("found node %s", node.Name)
outer:
	for {
		if err == nil {
			for _, c := range node.Status.Conditions {
				if c.Type == core.NodeNetworkUnavailable {
					if c.Status == core.ConditionFalse {
						this.Controller().Infof("node network is ready: %s/%s", c.Reason, c.Message)
						break outer
					}
				}
			}
		}
		this.Controller().Infof("waiting for node network to become ready...")
		time.Sleep(10 * time.Second)
		_, err = resc.Get(node)
		if err != nil {
			this.Controller().Infof("cannot get node: %s", err)
		}
	}

	/*
		for {
			if ip:=node.Annotations["projectcalico.org/IPv4Address"]; ip!="" {
				this.Controller().Infof("calico uses node IP %s", ip)
				break
			}
			this.Controller().Infof("waiting for calico to become ready...")
			time.Sleep(10 * time.Second)
			_, err = resc.Get(node)
			if err != nil {
				this.Controller().Infof("cannot get node: %s", err)
			}
		}
	*/
}
