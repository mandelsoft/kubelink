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
	"io"
	"net"
	"sync"

	"golang.org/x/net/ipv4"

	"github.com/mandelsoft/k8sbridge/pkg/kubelink"
	"github.com/mandelsoft/k8sbridge/pkg/tcp"
)

const BufferSize = 17000

type ConnectionFailHandler interface {
	NotifyFailed(*TunnelConnection, error)
}

type TunnelConnection struct {
	lock           sync.RWMutex
	mux            *Mux
	conn           net.Conn
	clusterAddress net.IP
	remoteAddress  string
	handlers       []ConnectionFailHandler
}

func (this *TunnelConnection) String() string {
	return fmt.Sprintf("%s[%s]", this.clusterAddress, this.remoteAddress)
}

func DialTunnelConnection(mux *Mux, link *kubelink.Link, handlers ...ConnectionFailHandler) (*TunnelConnection, error) {
	conn, err := net.Dial("tcp", link.Endpoint)
	if err != nil {
		return nil, err
	}

	t := &TunnelConnection{
		mux:            mux,
		clusterAddress: link.ClusterAddress,
		conn:           conn,
		remoteAddress:  conn.RemoteAddr().String(),
		handlers:       append(handlers[:0:0], handlers...),
	}
	go func() {
		defer t.mux.RemoveTunnel(t)
		t.mux.NotifyFailed(t, t.Serve())
	}()
	return t, nil
}

func (this *TunnelConnection) RegisterFailHandler(handlers ...ConnectionFailHandler) {
	this.lock.Lock()
	defer this.lock.Unlock()

	this.handlers = append(this.handlers, handlers...)
}

func (this *TunnelConnection) notify(err error) {
	this.lock.RLock()
	defer this.lock.RUnlock()
	for _, h := range this.handlers {
		h.NotifyFailed(this, err)
	}
}

func ServeTunnelConnection(mux *Mux, conn net.Conn) {
	t := &TunnelConnection{
		mux:           mux,
		conn:          conn,
		remoteAddress: conn.RemoteAddr().String(),
	}
	t.Serve()
}

////////////////////////////////////////////////////////////////////////////////

func (this *TunnelConnection) Close() error {
	return this.conn.Close()
}

func (this *TunnelConnection) Serve() error {
	var buffer [BufferSize]byte
	bytes := buffer[:]
	log := this.mux.NewContext("remote", this.remoteAddress)
	for {
		n, err := this.ReadPacket(bytes)
		if n <= 0 || err != nil {
			log.Errorf("END: %d bytes, err=%s", n, err)
			if n <= 0 {
				err = io.EOF
			}
			return err
		}
		packet := bytes[:n]
		vers := int(packet[0]) >> 4
		if vers == ipv4.Version {
			header, err := ipv4.ParseHeader(packet)
			if err != nil {
				log.Errorf("err: %s", err)
			} else {
				log.Infof("receiving ipv4[%d]: (%d) hdr: %d, total: %d, prot: %d,  %s->%s\n",
					header.Version, len(packet), header.Len, header.TotalLen, header.Protocol, header.Src, header.Dst)
			}
			if len(this.mux.local) > 0 {
				use := false
				for _, cidr := range this.mux.local {
					if cidr.Contains(header.Dst) {
						use = true
						break
					}
				}
				if !use {
					log.Warnf("dropping packet to %q", header.Dst)
				}
			}
		}
		o, err := this.mux.tun.Write(bytes[:n])
		if err != nil {
			return err
		}
		if n != o {
			panic(fmt.Errorf("packet length %d, but written %d", n, o))
		}
	}
}

func (this *TunnelConnection) read(r io.Reader, data []byte) error {
	start := 0
	for start == len(data) {
		n, err := r.Read(data[start:])
		if err != nil {
			return err
		}
		start += n
	}
	return nil
}

func (this *TunnelConnection) write(w io.Writer, data []byte) error {
	start := 0
	for start < len(data) {
		n, err := w.Write(data[start:])
		if err != nil {
			return err
		}
		start += n
	}
	return nil
}

func (this *TunnelConnection) ReadPacket(data []byte) (int, error) {
	lbuf := [2]byte{}
	err := this.read(this.conn, lbuf[:])

	if err != nil {
		return 0, err
	}

	length := tcp.NtoHs(lbuf[:])
	if int(length) > len(data) {
		return 0, fmt.Errorf("buffer too small (%d): packet size is %d", len(data), length)
	}
	return int(length), this.read(this.conn, data[0:length])
}

func (this *TunnelConnection) WritePacket(data []byte) error {
	if len(data) > 65535 {
		return fmt.Errorf("packet too large (%d)", len(data))
	}
	lbuf := tcp.HtoNs(uint16(len(data)))
	err := this.write(this.conn, lbuf)
	if err != nil {
		return err
	}
	return this.write(this.conn, data)
}
