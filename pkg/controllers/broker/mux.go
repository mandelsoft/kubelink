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
	lock   sync.RWMutex
	ctx    context.Context
	byIP   map[string]*TunnelConnection
	errors map[string]error

	links    *kubelink.Links
	local    []net.IPNet
	tun      *Tun
	handlers []LinkFailHandler
}

func NewMux(ctx context.Context, logger logger.LogContext, localCIDRs []net.IPNet, tun *Tun, links *kubelink.Links, handlers ...LinkFailHandler) *Mux {
	return &Mux{
		LogContext: logger,
		ctx:        ctx,
		links:      links,
		byIP:       map[string]*TunnelConnection{},
		errors:     map[string]error{},
		tun:        tun,
		local:      localCIDRs,
		handlers:   append(handlers[:0:0], handlers...),
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

func (this *Mux) GetConnection(ip net.IP) *TunnelConnection {
	this.lock.RLock()

	ips := ip.String()

	t := this.byIP[ips]
	if t != nil {
		this.lock.RUnlock()
		return t
	}
	l, _ := this.links.GetLinkForIP(ip)

	if l == nil {
		this.lock.RUnlock()
		return nil
	}
	t = this.byIP[l.ClusterAddress.String()]
	if t != nil {
		this.lock.RUnlock()
		return t
	}
	this.lock.RUnlock()
	return this.AssureTunnel(l)
}

func (this *Mux) RemoveTunnel(t *TunnelConnection) {
	this.lock.Lock()
	defer this.lock.Unlock()

	t.Close()
	delete(this.byIP, t.clusterAddress.String())
}

func (this *Mux) NotifyFailed(t *TunnelConnection, err error) {
	this.lock.Lock()
	defer this.lock.Unlock()

	this.Errorf("connection %s aborted; %s", t, err)
	this.errors[t.clusterAddress.String()] = err
	t.Close()
	delete(this.byIP, t.clusterAddress.String())
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

func (this *Mux) AssureTunnel(link *kubelink.Link) *TunnelConnection {
	this.lock.Lock()
	defer this.lock.Unlock()

	ips := link.ClusterAddress.String()
	t := this.byIP[ips]
	if t != nil {
		return t
	}
	t, err := DialTunnelConnection(this, link, this)
	if err != nil {
		this.errors[ips] = err
		logger.Errorf("cannot initialize connection to %s: %s", link, err)
		return nil
	}
	delete(this.errors, ips)
	this.byIP[ips] = t
	return t
}

func (this *Mux) Close(ip net.IP) error {
	this.lock.Lock()
	defer this.lock.Unlock()

	ips := ip.String()
	t := this.byIP[ips]
	if t == nil {
		return nil
	}
	delete(this.byIP, ips)
	delete(this.errors, ips)
	return t.Close()
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

		t := this.GetConnection(header.Dst)
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
	for {
		n, err := this.tun.Read(bytes)
		if n <= 0 || err != nil {
			if err.Error()== "read /dev/net/tun: not pollable" {
				this.Infof("shit")
				this.tun.tun.ReadWriteCloser.(*os.File).Fd()
				continue
			}
			this.Errorf("END: %d bytes, err=%s", n, err)
			if n <= 0 {
				err = io.EOF
			}
			return err
		}
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

func (this *Mux) ServeConnection(ctx context.Context, c net.Conn) {
	ServeTunnelConnection(this, c)
}
