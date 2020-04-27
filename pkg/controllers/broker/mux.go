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
	"context"
	"crypto/tls"
	"io"
	"net"
	"os"
	"sync"

	"github.com/gardener/controller-manager-library/pkg/logger"
	"golang.org/x/net/ipv4"

	"github.com/mandelsoft/k8sbridge/pkg/kubelink"
)

type LinkFailHandler interface {
	NotifyFailed(*kubelink.Link, error)
}

type Mux struct {
	logger.LogContext
	lock        sync.RWMutex
	ctx         context.Context
	certInfo    *CertInfo
	byClusterIP map[string][]*TunnelConnection
	errors      map[string]error

	clusterCIDR *net.IPNet
	links       *kubelink.Links
	local       []net.IPNet
	tun         *Tun
	handlers    []LinkFailHandler
}

func NewMux(ctx context.Context, logger logger.LogContext, certInfo *CertInfo, clusterCIDR *net.IPNet, localCIDRs []net.IPNet, tun *Tun, links *kubelink.Links, handlers ...LinkFailHandler) *Mux {
	return &Mux{
		LogContext:  logger,
		ctx:         ctx,
		certInfo:    certInfo,
		links:       links,
		byClusterIP: map[string][]*TunnelConnection{},
		errors:      map[string]error{},
		tun:         tun,
		clusterCIDR: clusterCIDR,
		local:       localCIDRs,
		handlers:    append(handlers[:0:0], handlers...),
	}
}

func (this *Mux) GetError(ip net.IP) error {
	this.lock.RLock()
	defer this.lock.RUnlock()

	return this.errors[ip.String()]
}

func (this *Mux) RegisterFailHandler(handlers ...LinkFailHandler) {
	this.lock.Lock()
	defer this.lock.Unlock()

	this.handlers = append(this.handlers, handlers...)
}

func (this *Mux) queryClusterConnection(ip net.IP) (*TunnelConnection, string) {
	ips := ip.String()

	for _, t := range this.byClusterIP[ips] {
		return t, ips
	}
	return nil, ips
}

func (this *Mux) QueryConnectionForIP(ip net.IP) (*TunnelConnection, *kubelink.Link) {
	this.lock.RLock()
	defer this.lock.RUnlock()

	t, _ := this.queryClusterConnection(ip)
	if t != nil {
		return t, nil
	}
	l, _ := this.links.GetLinkForIP(ip)
	if l == nil {
		return nil, nil
	}
	t, _ = this.queryClusterConnection(l.ClusterAddress)
	return t, l
}

func (this *Mux) GetConnectionForIP(ip net.IP) *TunnelConnection {

	t, l := this.QueryConnectionForIP(ip)
	if t != nil || l == nil {
		return t
	}
	return this.AssureTunnel(l)
}

func (this *Mux) AssureTunnel(link *kubelink.Link) *TunnelConnection {
	this.lock.Lock()
	defer this.lock.Unlock()

	t, ips := this.queryClusterConnection(link.ClusterAddress)
	if t != nil {
		return t
	}
	t, err := DialTunnelConnection(this, link, this)
	if err != nil {
		this.errors[ips] = err
		logger.Errorf("cannot initialize connection to %s: %s", link, err)
		return nil
	}
	this.addTunnel(t)
	return t
}

func (this *Mux) AddTunnel(t *TunnelConnection) {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.addTunnel(t)
}

func (this *Mux) addTunnel(t *TunnelConnection) {
	if t.clusterAddress != nil {
		ips := t.clusterAddress.String()
		delete(this.errors, ips)
		list := this.byClusterIP[ips]
		for _, c := range list {
			if c == t {
				return
			}
		}
		this.byClusterIP[ips] = append(list, t)
	}
}

func (this *Mux) RemoveTunnel(t *TunnelConnection) {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.removeTunnel(t)
}

func (this *Mux) removeTunnel(t *TunnelConnection) {
	ips := t.clusterAddress.String()
	t.Close()
	list := this.byClusterIP[ips]
	if len(list) > 0 {
		for i, c := range list {
			if c == t {
				list = append(list[:i], list[i+1:]...)
				break
			}
		}
	}
	if len(list) == 0 {
		delete(this.byClusterIP, ips)
	} else {
		this.byClusterIP[ips] = list
	}
}

func (this *Mux) NotifyFailed(t *TunnelConnection, err error) {
	this.lock.Lock()
	defer this.lock.Unlock()

	if err != nil {
		this.Errorf("connection %s aborted; %s", t, err)
	}
	this.errors[t.clusterAddress.String()] = err
	this.removeTunnel(t)
	l, _ := this.links.GetLinkForIP(t.clusterAddress)
	if l != nil {
		this.notify(l, err)
	}
}

func (this *Mux) notify(l *kubelink.Link, err error) {
	for _, h := range this.handlers {
		h.NotifyFailed(l, err)
	}
}

func (this *Mux) Close(ip net.IP) error {
	this.lock.Lock()
	defer this.lock.Unlock()

	var err error
	ips := ip.String()
	for _, t := range this.byClusterIP[ips] {
		err2 := t.Close()
		if err2 != nil {
			err = err2
		}
	}
	delete(this.byClusterIP, ips)
	delete(this.errors, ips)
	return err
}

////////////////////////////////////////////////////////////////////////////////

func (this *Mux) FindConnection(packet []byte) *TunnelConnection {
	vers := int(packet[0]) >> 4
	if vers == ipv4.Version {
		header, err := ipv4.ParseHeader(packet)
		if err != nil {
			this.Errorf("err: %s", err)
			return nil
		}

		t := this.GetConnectionForIP(header.Dst)
		if t != nil {
			this.Infof("to %q: ipv4[%d]: (%d) hdr: %d, total: %d, prot: %d,  %s->%s\n", t.remoteAddress, header.Version, len(packet), header.Len, header.TotalLen, header.Protocol, header.Src, header.Dst)
			return t
		}
		this.Warnf("drop unknown dest: ipv4[%d]: (%d) hdr: %d, total: %d, prot: %d,  %s->%s\n", header.Version, len(packet), header.Len, header.TotalLen, header.Protocol, header.Src, header.Dst)
	} else {
		this.Warnf("drop unknown packet (type %d)", vers)
	}
	return nil
}

func (this *Mux) HandleTun() error {
	var buffer [BufferSize]byte
	bytes := buffer[:]
	working := false
	for {
		n, err := this.tun.Read(bytes)
		if n <= 0 || err != nil {
			if err.Error() == "read /dev/net/tun: not pollable" {
				if working {
					this.Errorf("handle tun: err=%s", err)
				}
				this.tun.tun.ReadWriteCloser.(*os.File).Close()
				return nil
			}
			if working {
				this.Errorf("END: %d bytes, err=%s", n, err)
			}
			if n <= 0 {
				err = io.EOF
			}
			return err
		}
		working = true
		packet := bytes[:n]
		t := this.FindConnection(packet)
		if t != nil {
			err = t.WritePacket(packet)
			if err != nil {
				return err
			}
		}
	}
}

func (this *Mux) ServeConnection(ctx context.Context, conn net.Conn) {
	var clusterAddress net.IP
	remote := conn.RemoteAddr().String()

	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if ok {
		state := tlsConn.ConnectionState()
		printConnState(this, state)
		if len(state.PeerCertificates) > 0 {
			cn := state.PeerCertificates[0].Subject.CommonName
			l := this.links.GetLinkForEndpoint(cn)
			if l == nil {
				this.Errorf("unknown endpoint %s for connection from %s", cn, remote)
				return
			}
			this.Infof("new tunnel connection for %s[%s] from %s", l.Name, l.ClusterAddress, remote)
			clusterAddress = l.ClusterAddress
		}
	}
	t := &TunnelConnection{
		mux:            this,
		conn:           conn,
		clusterAddress: clusterAddress,
		remoteAddress:  remote,
	}
	if t.clusterAddress != nil {
		this.AddTunnel(t)
		defer this.RemoveTunnel(t)
	}
	t.Serve()
}
