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

package wireguard

import (
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/gardener/controller-manager-library/pkg/utils"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	corev1 "k8s.io/api/core/v1"

	"github.com/mandelsoft/kubelink/pkg/controllers"
	"github.com/mandelsoft/kubelink/pkg/controllers/broker/config"
	"github.com/mandelsoft/kubelink/pkg/controllers/broker/runmode"
	"github.com/mandelsoft/kubelink/pkg/iptables"
	"github.com/mandelsoft/kubelink/pkg/kubelink"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

const PrivateKey = "WireguardPrivateKey"
const DefaultPort = 8777

type mode struct {
	runmode.RunModeBase
	config *config.Config

	port int
	key  *wgtypes.Key

	link netlink.Link

	lock   sync.Mutex
	err    error            // error configuring wireguard device
	errors map[string]error // error for a dedicated cluster address
}

var _ runmode.RunMode = &mode{}

func NewWireguardMode(env runmode.RunModeEnv) (runmode.RunMode, error) {
	this := &mode{
		RunModeBase: runmode.NewRunModeBase(config.RUN_MODE_WIREGUARD, env),
		config:      env.Config(),
		errors:      map[string]error{},
	}
	if this.config.Port == 0 {
		this.config.Port = DefaultPort
	}
	if this.config.Service != "" {
		this.Infof("using wireguard service %q", this.config.Service)
	} else {
		this.port = this.config.Port
		this.Infof("using wireguard port %d", this.port)
	}
	return this, nil
}

func (this *mode) Setup() error {
	if this.config.Service == "" {
		this.Infof("using configured wireguard port %d", this.port)
		return nil
	}
	// analyse and validate service
	port, err := controllers.GetServicePort(this.Controller(), this.config.Service, "wireguard", corev1.ProtocolUDP)
	if err != nil {
		return err
	}
	this.port = port
	this.Infof("using wireguard port %d from service %q", port, this.config.Service)
	return nil
}

func (this *mode) Start() error {
	name := resources.NewObjectName(this.Controller().GetEnvironment().ControllerManager().GetNamespace(), this.config.Secret)
	// catch secret updates for private key secret
	this.Secrets().AddNotificationHandler(controllers.NotificationFunction(this.handleSecret), name)
	return nil
}

func (this *mode) GetInterface() netlink.Link {
	return this.link
}

func (this *mode) GetErrorForMeshNode(ip net.IP) error {
	this.lock.Lock()
	defer this.lock.Unlock()

	if this.err != nil {
		return this.err
	}
	return this.errors[ip.String()]
}

func (this *mode) RequiredIPTablesChains() iptables.Requests {
	chains := this.Links().GetFirewallChains()
	if chains == nil {
		chains = iptables.Requests{}
	}
	return chains
}

func (this *mode) ReconcileInterface(logger logger.LogContext) error {
	link, err := netlink.LinkByName(this.config.Interface)

	if IsLinkNotFound(err) {
		if !this.Links().HasWireguard() {
			this.link = nil
			return nil
		}
		this.Controller().Infof("creating wireguard interface %q", this.config.Interface)
		attrs := netlink.NewLinkAttrs()
		attrs.Name = this.config.Interface
		link = &netlink.GenericLink{
			LinkAttrs: attrs,
			LinkType:  "wireguard",
		}
		err = netlink.LinkAdd(link)
	}
	if err != nil {
		this.link = nil
		return fmt.Errorf("error providing wireguard interface %q: %s", this.config.Interface, err)
	}
	this.link = link
	this.config.Interface = link.Attrs().Name

	wg, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer wg.Close()

	err = this.Env().LinkTool().PrepareLink(link, this.config.ClusterAddress)
	if err != nil {
		return err
	}
	if this.key == nil {
		return fmt.Errorf("no private key available")
	}

	dev, err := wg.Device(this.link.Attrs().Name)
	if err != nil {
		return err
	}
	update := false
	if dev.PrivateKey.String() != this.key.String() || dev.ListenPort != this.port {
		logger.Infof("update interface %q with key %s and port %d", this.link.Attrs().Name, this.key.PublicKey(), this.port)
		update = true
	}
	port := this.port
	config := wgtypes.Config{
		PrivateKey: this.key,
		ListenPort: &port,
	}

	keep := 21 * time.Second
	found := utils.StringSet{}
	this.Links().Visit(func(l *kubelink.Link) bool {
		if l.PublicKey != nil {
			ip := net.ParseIP(l.Host)
			if ip == nil {
				ips, err := net.LookupIP(l.Host)
				if err != nil {
					this.propagateError(nil, err, l.ClusterAddress)
					return true
				}
				sort.Slice(ips, func(a, b int) bool { return strings.Compare(ips[a].String(), ips[b].String()) < 0 })
				ip = ips[0]
			}
			allowed := []net.IPNet{
				*tcp.IPtoCIDR(l.ClusterAddress.IP),
			}
			for _, e := range l.Egress {
				allowed = append(allowed, *e)
			}
			peer := wgtypes.PeerConfig{
				PublicKey: *l.PublicKey,
				Endpoint: &net.UDPAddr{
					Port: l.Port,
					IP:   ip,
				},
				PersistentKeepaliveInterval: &keep,
				AllowedIPs:                  allowed,
			}
			for _, p := range dev.Peers {
				if equalKey(&p.PublicKey, &peer.PublicKey) {
					found.Add(p.PublicKey.String())
					if !equalUDPAddr(p.Endpoint, peer.Endpoint) {
						continue
					}
					if !equalIPNetList(p.AllowedIPs, peer.AllowedIPs) {
						peer.ReplaceAllowedIPs = true
						continue
					}
					if p.PersistentKeepaliveInterval != keep {
						continue
					}
					return true
				}
			}
			logger.Infof("  update peer %s: %s %s", peer.PublicKey, peer.Endpoint, list(peer.AllowedIPs))
			config.Peers = append(config.Peers, peer)
			update = true
			this.propagateError(nil, nil, l.ClusterAddress)
		}
		return true
	})

	remove := 0
	for _, p := range dev.Peers {
		if !found.Contains(p.PublicKey.String()) {
			peer := wgtypes.PeerConfig{
				PublicKey: p.PublicKey,
				Remove:    true,
			}
			logger.Infof("  remove peer %s: %s %s", p.PublicKey, p.Endpoint, list(p.AllowedIPs))
			config.Peers = append(config.Peers, peer)
			update = true
			remove++
		}
	}

	if update {
		logger.Infof("update interface with %d peer updates and %d removals", len(config.Peers)-remove, remove)
		err = wg.ConfigureDevice(this.link.Attrs().Name, config)
		this.propagateError(nil, err, nil)
	}
	return err
}

func list(this []net.IPNet) string {
	sep := "["
	end := ""
	s := ""
	for _, c := range this {
		s = fmt.Sprintf("%s%s%s", s, sep, c.String())
		sep = ","
		end = "]"
	}
	return s + end
}

func equalIPNetList(a, b []net.IPNet) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if len(a) != len(b) {
		return false
	}
next:
	for _, i := range a {
		for _, j := range b {
			if tcp.EqualCIDR(&i, &j) {
				continue next
			}
		}
		return false
	}
	return true
}

func equalUDPAddr(a, b *net.UDPAddr) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if !a.IP.Equal(b.IP) {
		return false
	}
	if a.Port != b.Port {
		return false
	}
	return true
}

func equalKey(a, b *wgtypes.Key) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

////////////////////////////////////////////////////////////////////////////////

func (this *mode) handleSecret(name resources.ObjectName, obj resources.Object) {
	this.Infof("handle update wireguard secret %q", name)
	if obj == nil {
		// secret not available
		this.propagateError(nil, fmt.Errorf("wireguard secret %q not available", this.config.Secret), nil)
		return
	}
	data := obj.Data().(*corev1.Secret).Data
	if len(data[PrivateKey]) == 0 {
		this.propagateError(nil, fmt.Errorf("missing data %q in wireguard secret %q", PrivateKey, this.config.Secret), nil)
		return
	}
	key, err := wgtypes.ParseKey(string(data[PrivateKey]))
	if err != nil {
		this.propagateError(nil, fmt.Errorf("invalid private key in wireguard secret %q: %s", this.config.Secret, err), nil)
		return
	}
	this.propagateError(nil, nil, nil)

	this.lock.Lock()
	defer this.lock.Unlock()
	//this.Infof("old key %q", this.key)
	//this.Infof("new key %q", key)
	if this.key == nil || key.String() != this.key.String() {
		this.key = &key
		this.Infof("setting private key with public key %q", key.PublicKey())
		this.TriggerUpdate()
	}
}

func (this *mode) propagateError(logger logger.LogContext, err error, addr *net.IPNet) {
	if logger == nil {
		logger = this.Controller()
	}
	if err != nil {
		if addr != nil {
			logger.Errorf("endpoint error for %q: %s", addr, err)
		} else {
			logger.Errorf("interface error: %s", err)
		}
	}
	this.lock.Lock()
	defer this.lock.Unlock()
	if addr == nil {
		this.err = err
	} else {
		this.errors[addr.IP.String()] = err
	}
}

var lnf = reflect.TypeOf(&netlink.LinkNotFoundError{}).Elem()

func IsLinkNotFound(err error) bool {
	return err != nil && reflect.ValueOf(err).Type() == lnf
}
