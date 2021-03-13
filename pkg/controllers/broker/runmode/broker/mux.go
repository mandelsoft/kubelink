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
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/gardener/controller-manager-library/pkg/logger"
	"golang.org/x/net/ipv4"

	"github.com/mandelsoft/kubelink/pkg/kubelink"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

type ConnectionHandler interface {
	UpdateAccess(hello *ConnectionHello)
	GetAccess() kubelink.LinkAccessInfo
	GetDNSInfo() kubelink.LinkDNSInfo
}

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

	port     uint16
	links    *kubelink.Links
	local    tcp.CIDRList
	tun      *Tun
	handlers []LinkStateHandler

	connectionHandler ConnectionHandler
	autoconnect       bool
}

func NewMux(ctx context.Context, logger logger.LogContext, certInfo *CertInfo, port uint16, localCIDRs tcp.CIDRList, tun *Tun, links *kubelink.Links, handlers ...LinkStateHandler) *Mux {
	return &Mux{
		LogContext:  logger,
		ctx:         ctx,
		certInfo:    certInfo,
		links:       links,
		byClusterIP: map[string][]*TunnelConnection{},
		errors:      map[string]error{},
		tun:         tun,
		port:        port,
		local:       localCIDRs,
		handlers:    append(handlers[:0:0], handlers...),
	}
}

func (this *Mux) SetAutoConnect(b bool) {
	this.autoconnect = b
}

func (this *Mux) GetError(ip net.IP) error {
	if this == nil {
		return nil
	}
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
	l := this.links.GetLinkForIP(ip)
	if l == nil {
		return nil, nil
	}
	t, _ = this.queryClusterConnection(l.ClusterAddress.IP)
	return t, l
}

func (this *Mux) GetConnectionForIP(ip net.IP) (*TunnelConnection, error) {

	t, l := this.QueryConnectionForIP(ip)
	if t != nil || l == nil {
		return t, nil
	}
	return this.AssureTunnel(this, l)
}

func (this *Mux) AssureTunnel(logger logger.LogContext, link *kubelink.Link) (*TunnelConnection, error) {
	this.lock.Lock()
	defer this.lock.Unlock()

	t, ips := this.queryClusterConnection(link.ClusterAddress.IP)
	if t != nil {
		return t, nil
	}
	t, err := this.dialTunnelConnection(link)
	if err != nil {
		this.errors[ips] = err
		logger.Errorf("cannot initialize connection to %s: %s", link, err)
		return nil, err
	}
	this.Infof("connection accepted by remote side")
	this.addTunnel(t)
	go func() {
		defer t.mux.RemoveTunnel(t)
		this.Infof("serving connection to %s", t.String())
		t.Serve()
	}()
	return t, nil
}

func (this *Mux) dialTunnelConnection(link *kubelink.Link) (*TunnelConnection, error) {
	if this.certInfo.UseTLS() {
		this.Infof("dialing for %s to %s with client certificate", link.Name, link.Endpoint)
	} else {
		this.Infof("dialing for %s to %s", link.Name, link.Endpoint)
	}
	conn, err := this.certInfo.Dial(link.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("dialing failed: %s", err)
	}
	t, hello, err := NewTunnelConnection(this, conn, link, this.links)
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = hello
	return t, nil
}

func (this *Mux) AddTunnel(t *TunnelConnection) {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.addTunnel(t)
}

func (this *Mux) addTunnel(t *TunnelConnection) {
	if t.targetAddress != nil {
		ips := t.targetAddress.IP.String()
		delete(this.errors, ips)
		list := this.byClusterIP[ips]
		for _, c := range list {
			if c == t {
				this.Infof("tunnel for %s already registered", ips)
				return
			}
		}
		this.Infof("adding tunnel for %s", ips)
		this.errors[ips] = nil
		this.byClusterIP[ips] = append(list, t)
		l := this.links.GetLinkForClusterAddress(t.targetAddress.IP)
		this.notify(l, nil)
	}
}

func (this *Mux) RemoveTunnel(t *TunnelConnection) {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.removeTunnel(t)
}

func (this *Mux) removeTunnel(t *TunnelConnection) {
	this.Infof("removing tunnel")
	ips := t.targetAddress.IP.String()
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

	this.errors[t.targetAddress.IP.String()] = err
	if err != nil {
		this.Errorf("connection %s aborted: %s", t, err)
		this.removeTunnel(t)
	}
	l := this.links.GetLinkForIP(t.targetAddress.IP)
	this.notify(l, err)
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

		t, _ := this.GetConnectionForIP(header.Dst)
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
		if n < 0 || err != nil {
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
		if n == 0 {
			continue
		}
		working = true
		packet := bytes[:n]
		this.Send(log, packet)
	}
}

func (this *Mux) Send(log logger.LogContext, packet []byte) error {
	var err error
	t := this.FindConnection(log, packet)
	if t != nil {
		err = t.Send(packet)
		if err != nil {
			log.Warnf("%s", err)
		}
	}
	return err
}

func (this *Mux) ServeConnection(ctx context.Context, conn net.Conn) {
	var link *kubelink.Link
	defer conn.Close()
	fqdn := ""
	remote := conn.RemoteAddr().String()

	tlsConn, ok := conn.(*tls.Conn)
	if ok {
		state := tlsConn.ConnectionState()
		this.Infof("handle inbound connection request")
		printConnState(this, state)
		if len(state.PeerCertificates) > 0 {
			fqdn = state.PeerCertificates[0].Subject.CommonName
			link = this.links.GetLinkForEndpoint(fqdn)
			if link == nil {
				if !this.autoconnect {
					this.Errorf("unknown endpoint %s for connection from %s", fqdn, remote)
					return
				}
				this.Infof("tunnel connection requested for %s from %s-> using auto-connect", fqdn, remote)
			} else {
				this.Infof("tunnel connection for %s (%s[%s]) requested from %s", link.Name, fqdn, link.ClusterAddress.IP, remote)
			}
		}
	} else {
		this.Infof("tunnel connection requested from %s", remote)
	}
	t, hello, err := NewTunnelConnection(this, conn, link, this.links)
	if err != nil {
		this.Errorf("initiating tunnel from %s failed: %s", remote, err)
		return
	}
	cidr := hello.GetClusterAddress()
	if t.targetAddress != nil {
		if !t.targetAddress.Contains(cidr.IP) {
			this.Errorf("remote cluster (%s) not in local range %s", cidr.IP, t.targetAddress)
			return
		}
		if !cidr.Contains(t.targetAddress.IP) {
			this.Errorf("local cluster (%s) not in remote range %s", t.targetAddress.IP, cidr)
			return
		}
	} else {
		if !this.autoconnect {
			this.Errorf("no auto connect for unknown cluster %s", cidr)
			return
		}
		adjusted := *cidr
		m := this.links.GetMeshForClusterAddress(cidr.IP)
		if m == nil {
			this.Errorf("cannot auto-connect cluster %s for unknown mesh", cidr.IP, err)
			return
		}
		adjusted.Mask = t.localAddress.Mask
		if hello.GetPort() > 0 {
			fqdn = fmt.Sprintf("%s:%d", fqdn, hello.GetPort())
		}
		l, err := this.links.RegisterLink(DefaultLinkName(cidr.IP), &adjusted, fqdn, hello.GetCIDR())
		if err != nil {
			this.Errorf("cannot auto-connect cluster %s: %s", cidr.IP, err)
			return
		}
		this.Infof("auto-connected %s", l)
		t.targetAddress = cidr
	}
	if t.name == "" {
		link := this.links.GetLinkForClusterAddress(cidr.IP)
		if link == nil {
			this.Errorf("oops, finally for link found for %s", cidr.IP)
			return
		}
		t.ApplyLink(link.Name)
	}
	t.Infof("connection request finally accepted")
	defer this.RemoveTunnel(t)
	this.AddTunnel(t)
	t.Serve()
}

func DefaultLinkName(ip net.IP) string {
	s := ip.String()
	s = strings.ReplaceAll(s, ".", "-")
	s = strings.ReplaceAll(s, ":", "-")
	return s
}
