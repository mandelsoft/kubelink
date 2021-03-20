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
	"sort"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/kubelink"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

type Peers map[string]*Peer

type Peer struct {
	Links        kubelink.LinkNameSet
	PublicKey    wgtypes.Key
	PresharedKey *wgtypes.Key
	Host         string
	Port         int
	Endpoint     *net.UDPAddr
	AllowedIPs   tcp.CIDRList
	Error        error
}

func (this Peers) Assure(name kubelink.LinkName, pub wgtypes.Key) *Peer {
	k := pub.String()
	p := this[k]
	if p == nil {
		p = &Peer{
			Links:     kubelink.LinkNameSet{},
			PublicKey: pub,
		}
		this[k] = p
	}
	p.Links.Add(name)
	return p
}

func (this *Peer) AddPresharedKey(key *wgtypes.Key) error {
	if this.PresharedKey == nil {
		this.PresharedKey = key
	} else {
		if key != nil && *key != *this.PresharedKey {
			this.Error = fmt.Errorf("preshared key mismatch")
			return this.Error
		}
	}
	return nil
}

func (this *Peer) SetEndpoint(l *kubelink.Link) error {
	this.Links.Add(l.Name)
	if l.Endpoint != api.EP_INBOUND {
		ip := net.ParseIP(l.Host)
		if ip == nil {
			ips, err := net.LookupIP(l.Host)
			if err != nil {
				return err
			}
			sort.Slice(ips, func(a, b int) bool { return strings.Compare(ips[a].String(), ips[b].String()) < 0 })
			if this.Endpoint != nil {
				for _, v := range ips {
					if v.Equal(this.Endpoint.IP) {
						ip = v
					}
				}
			}
			if ip == nil {
				ip = ips[0]
			}
		}

		if this.Endpoint != nil {
			if !this.Endpoint.IP.Equal(ip) && this.Host != l.Host {
				this.Error = fmt.Errorf("inconsistent endpoint host setting for equivalent links %s", this.Links)
				return this.Error
			}
			if this.Endpoint.Port != l.Port {
				this.Error = fmt.Errorf("inconsistent endpoint port setting for equivalent links %s", this.Links)
				return this.Error

			}
		} else {
			this.Endpoint = &net.UDPAddr{
				Port: l.Port,
				IP:   ip,
			}
		}
	}
	return nil
}

var keepAlive = 21 * time.Second

func (this *Peer) AddAllowedIPs(links kubelink.Links, l *kubelink.Link) {
	if l == nil {
		return
	}
	// Allow peer's mesh IP
	this.AllowedIPs.Enrich(tcp.IPtoCIDR(l.ClusterAddress.IP))

	// Allow configured peer egress
	this.AllowedIPs.Enrich(l.Egress...)

	// Allow gateway traffic
	if links != nil {
		for r := range l.GatewayFor {
			this.AddAllowedIPs(nil, links.GetLink(r))
		}
	}
}

func (this *Peer) GetConfig() *wgtypes.PeerConfig {
	allowed := make([]net.IPNet, len(this.AllowedIPs), len(this.AllowedIPs))
	for i, c := range this.AllowedIPs {
		allowed[i] = *c
	}
	return &wgtypes.PeerConfig{
		PublicKey:                   this.PublicKey,
		PresharedKey:                this.PresharedKey,
		Endpoint:                    this.Endpoint,
		PersistentKeepaliveInterval: &keepAlive,
		AllowedIPs:                  allowed,
	}
}
