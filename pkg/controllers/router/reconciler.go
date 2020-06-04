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

package router

import (
	"net"
	"time"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/vishvananda/netlink"

	"github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/controllers"
	"github.com/mandelsoft/kubelink/pkg/kubelink"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

type reconciler struct {
	*controllers.Reconciler
	config *Config
}

var _ reconcile.Interface = &reconciler{}
var _ controllers.ReconcilerImplementation = &reconciler{}

///////////////////////////////////////////////////////////////////////////////

func (this *reconciler) Config(cfg interface{}) *controllers.Config {
	return &cfg.(*Config).Config
}

func (this *reconciler) Gateway(obj *v1alpha1.KubeLink) (net.IP, error) {
	return nil, nil
}

func (this *reconciler) UpdateGateway(link *v1alpha1.KubeLink) *string {
	return nil
}

func (this *reconciler) IsManagedRoute(route *netlink.Route, routes kubelink.Routes) bool {
	if route.Dst != nil {
		if this.config.PodCIDR.Contains(route.Dst.IP) {
			return false
		}
		if route.Gw != nil && route.LinkIndex == this.NodeInterface().Index {
			return true
		}
		for _, r := range routes {
			if tcp.EqualCIDR(route.Dst, r.Dst) {
				return true
			}
		}
	}
	return false
}

func (this *reconciler) RequiredRoutes() kubelink.Routes {
	return this.Links().GetRoutes(this.NodeInterface())
}

func (this *reconciler) RequiredSNATRules() *kubelink.Chain {
	return this.Links().GetSNATRules(this.NodeInterface())
}

func (this *reconciler) waitIPIP() {
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

func (this *reconciler) Setup() {
	if this.config.IPIP {
		this.waitIPIP()
		/*
			link := &netlink.Iptun{LinkAttrs: netlink.LinkAttrs{Name: "tunl0"}}
			err := netlink.LinkAdd(link)
			if err != nil && err != syscall.EEXIST {
				this.Controller().Errorf("error creating tunl0 interface: %s", err)
			} else {
				if err == nil {
					this.Controller().Infof("created interface tunl0[%d] for ip-over-ip routing option", link.Attrs().Index)
				} else {
					this.Controller().Infof("found interface tunl0[%d] for ip-over-ip routing option", link.Attrs().Index)
				}

				l, err := netlink.LinkByName("tunl0")
				if err != nil {
					this.Controller().Errorf("error getting tunl0 interface: %s", err)
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
								this.Controller().Errorf("cannot bring up tunl0: %s", err)
							} else {
								this.Controller().Errorf("bring up tunl0")
							}
						}
						/*
						ip, cidr, _ := net.ParseCIDR("192.168.0.1/32")
						cidr.IP = ip
						addr := &netlink.Addr{
							IPNet: &cidr,
						}
						addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
						found := false
						for _, oldAddr := range addrs {
							if address != nil && oldAddr.IP.Equal(address) {
								this.Controller.Infof("tunl0 address already present")
								found = true
								continue
							} else {
								this.Controller.Infof("tunl0 address found: %s", oldAddr)
								found = true
							}
						}

						if !found {
							logger.Infof("adding address %s to tunl0", cidr.String())
							err = netlink.AddrAdd(link, addr)
							if err != nil {
								this.Controller.Errorf("cannot add addr %q to tunl0: %s", cidr, err)
							}
						}
						* /
					} else {
						this.Controller().Errorf("tunl0 isn't an iptun device (%#v), please remove device and try again", l)
					}
				}
			}
		*/
	}
	this.Reconciler.Setup()
}
