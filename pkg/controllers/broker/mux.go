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

	"github.com/mandelsoft/kubelink/pkg/kubelink"
)

type LinkStateHandler interface {
	Notify(*kubelink.Link, error)
}

type Mux struct {
	logger.LogContext
	lock        sync.RWMutex
	ctx         context.Context
	certInfo    *CertInfo
	byClusterIP map[string][]*TunnelConnection
	errors      map[string]error

	cluster  *net.IPNet
	links    *kubelink.Links
	local    []net.IPNet
	tun      *Tun
	handlers []LinkStateHandler
}

func NewMux(ctx context.Context, logger logger.LogContext, certInfo *CertInfo, cluster *net.IPNet, localCIDRs []net.IPNet, tun *Tun, links *kubelink.Links, handlers ...LinkStateHandler) *Mux {
	return &Mux{
		LogContext:  logger,
		ctx:         ctx,
		certInfo:    certInfo,
		links:       links,
		byClusterIP: map[string][]*TunnelConnection{},
		errors:      map[string]error{},
		tun:         tun,
		cluster:     cluster,
		local:       localCIDRs,
		handlers:    append(handlers[:0:0], handlers...),
	}
}

func (this *Mux) GetError(ip net.IP) error {
	this.lock.RLock()
	defer this.lock.RUnlock()

	return this.errors[ip.String()]
}

func (this *Mux) RegisterFailHandler(handlers ...LinkStateHandler) {
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
		this.errors[ips] = nil
		this.byClusterIP[ips] = append(list, t)
		l := this.links.GetLinkForClusterAddress(t.clusterAddress)
		this.notify(l, nil)
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

func (this *Mux) Notify(t *TunnelConnection, err error) {
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
	if l != nil {
		for _, h := range this.handlers {
			h.Notify(l, err)
		}
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

func (this *Mux) FindConnection(log logger.LogContext, packet []byte) *TunnelConnection {
	vers := int(packet[0]) >> 4
	if vers == ipv4.Version {
		header, err := ipv4.ParseHeader(packet)
		if err != nil {
			log.Errorf("err: %s", err)
			return nil
		}

		t := this.GetConnectionForIP(header.Dst)
		if t != nil {
			log.Infof("receiving ipv4[%d]: (%d) hdr: %d, total: %d, prot: %d,  %s->%s to %s", header.Version, len(packet), header.Len, header.TotalLen, header.Protocol, header.Src, header.Dst, t.remoteAddress)
			return t
		}
		log.Warnf("drop unknown dest: ipv4[%d]: (%d) hdr: %d, total: %d, prot: %d,  %s->%s", header.Version, len(packet), header.Len, header.TotalLen, header.Protocol, header.Src, header.Dst)
	} else {
		log.Warnf("drop unknown packet (type %d)", vers)
	}
	return nil
}

func (this *Mux) HandleTun() error {
	log := this.NewContext("source", "tun")
	var buffer [BufferSize]byte
	bytes := buffer[:]
	working := false
	for {
		n, err := this.tun.Read(bytes)
		if n <= 0 || err != nil {
			if err.Error() == "read /dev/net/tun: not pollable" {
				if working {
					log.Errorf("handle tun: err=%s", err)
				}
				this.tun.tun.ReadWriteCloser.(*os.File).Close()
				return nil
			}
			if working {
				log.Errorf("END: %d bytes, err=%s", n, err)
			}
			if n <= 0 {
				err = io.EOF
			}
			return err
		}
		working = true
		packet := bytes[:n]
		t := this.FindConnection(log, packet)
		if t != nil {
			err = t.WritePacket(packet)
			if err != nil {
				return err
			}
		}
	}
}

func (this *Mux) ServeConnection(ctx context.Context, conn net.Conn) {
	remote := conn.RemoteAddr().String()
	this.Infof("new connection from %s", remote)
	var clusterAddress net.IP

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
