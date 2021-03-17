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
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	corev1 "k8s.io/api/core/v1"

	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
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

	finalizer func()

	peerstate map[kubelink.LinkName]runmode.LinkState
}

var _ runmode.RunMode = &mode{}

func NewWireguardMode(env runmode.RunModeEnv) (runmode.RunMode, error) {
	this := &mode{
		RunModeBase: runmode.NewRunModeBase(config.RUN_MODE_WIREGUARD, env),
		config:      env.Config(),
		errors:      map[string]error{},
		peerstate:   map[kubelink.LinkName]runmode.LinkState{},
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

func (this *mode) Cleanup() error {
	if this.finalizer != nil {
		this.finalizer()
	}
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

func (this *mode) UpdateLocalGatewayInfo(info *controllers.LocalGatewayInfo) {
	if this.key != nil {
		info.PublicKey = this.key.PublicKey().String()
	}
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

	addrs := this.Links().GetGatewayAddrs()
	natchains := this.Links().GetNatChains(addrs, link.Attrs().Name)
	this.finalizer, err = this.Env().LinkTool().PrepareLink(logger, link, addrs, natchains)
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
	keys := map[string]kubelink.LinkName{}
	links := kubelink.LinkNameSet{}
	this.Links().VisitLinks(func(l *kubelink.Link) bool {
		if l.PublicKey != nil && l.Endpoint != "" {
			links.Add(l.Name)
			var endpoint *net.UDPAddr
			if l.Endpoint != api.EP_INBOUND {
				ip := net.ParseIP(l.Host)
				if ip == nil {
					ips, err := net.LookupIP(l.Host)
					if err != nil {
						this.propagateError(nil, err, l)
						return true
					}
					sort.Slice(ips, func(a, b int) bool { return strings.Compare(ips[a].String(), ips[b].String()) < 0 })
					ip = ips[0]
				}
				endpoint = &net.UDPAddr{
					Port: l.Port,
					IP:   ip,
				}
			}
			allowed := []net.IPNet{}
			addAllowed(&allowed, l)
			for r := range l.GatewayFor {
				addAllowed(&allowed, this.Links().GetLink(r))
			}
			keys[(*l.PublicKey).String()] = l.Name
			peer := wgtypes.PeerConfig{
				PublicKey:                   *l.PublicKey,
				PresharedKey:                l.PresharedKey,
				Endpoint:                    endpoint,
				PersistentKeepaliveInterval: &keep,
				AllowedIPs:                  allowed,
			}
			for _, p := range dev.Peers {
				if equalKey(&p.PublicKey, &peer.PublicKey) {
					keys[p.PublicKey.String()] = l.Name
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
			this.propagateError(nil, nil, l)
		}
		return true
	})

	remove := 0
	offset := time.Now().Add(-3 * time.Minute)
	for _, p := range dev.Peers {
		pub := p.PublicKey.String()
		if n, ok := keys[pub]; ok {
			// for old peers check and remember peer state (new peers don't have a state yet)
			var newstate runmode.LinkState
			if p.LastHandshakeTime.Before(offset) {
				newstate = runmode.LinkState{
					State:   api.STATE_DOWN,
					Message: fmt.Sprintf("last handshake %s", p.LastHandshakeTime.String()),
				}
			} else {
				newstate = runmode.LinkState{
					State: api.STATE_UP,
				}
			}
			if this.peerstate[n] != newstate {
				this.peerstate[n] = newstate
				logger.Infof("  new peer state %s: %s %s", n, newstate.State, newstate.Message)
				this.TriggerLink(n)
			}
		} else {
			// delete unused peers
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

	// cleanup unused peer states
	for p := range this.peerstate {
		if _, ok := links[p]; !ok {
			delete(this.peerstate, p)
		}
	}
	if update {
		logger.Infof("update interface with %d peer updates and %d removals", len(config.Peers)-remove, remove)
		err = wg.ConfigureDevice(this.link.Attrs().Name, config)
		this.propagateError(nil, err, nil)
	}
	return err
}

func addAllowed(allowed *[]net.IPNet, l *kubelink.Link) {
	*allowed = append(*allowed, *tcp.IPtoCIDR(l.ClusterAddress.IP))
	for _, e := range l.Egress {
		*allowed = append(*allowed, *e)
	}
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
	update := false
	if this.key == nil || key.String() != this.key.String() {
		this.key = &key
		this.Infof("setting private key with public key %q", key.PublicKey())
		update = true
	}
	if update {
		this.TriggerUpdate()
	}
}

func (this *mode) propagateError(logger logger.LogContext, err error, link *kubelink.Link) {
	if logger == nil {
		logger = this.Controller()
	}
	if err != nil {
		if link != nil {
			logger.Errorf("endpoint error for %q: %s", link.Name, err)
		} else {
			logger.Errorf("interface error: %s", err)
		}
	}
	this.lock.Lock()
	defer this.lock.Unlock()
	if link == nil {
		this.err = err
	} else {
		old := this.errors[link.ClusterAddress.IP.String()]
		this.errors[link.ClusterAddress.IP.String()] = err
		if (err == nil) != (old == nil) || (old != nil && old.Error() != err.Error()) {
			this.TriggerLink(link.Name)
		}
	}
}

var lnf = reflect.TypeOf(&netlink.LinkNotFoundError{}).Elem()

func IsLinkNotFound(err error) bool {
	return err != nil && reflect.ValueOf(err).Type() == lnf
}

func (this *mode) GetLinkState(link *api.KubeLink) runmode.LinkState {
	ip, _, _ := net.ParseCIDR(link.Spec.ClusterAddress)
	this.lock.Lock()
	defer this.lock.Unlock()
	if ip != nil {
		err := this.errors[ip.String()]
		if err != nil {
			return runmode.LinkState{
				State:   api.STATE_ERROR,
				Message: err.Error(),
			}
		}
	}
	n := kubelink.DecodeLinkNameFromString(link.Name)
	return this.peerstate[n]
}
