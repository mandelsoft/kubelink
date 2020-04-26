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

package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/net/ipv4"

	"github.com/mandelsoft/k8sbridge/pkg/taptun"
)

const BufferSize = 17000

type Target struct {
	conn   net.Conn
	cidr   net.IPNet
	target string
}

type Tunnel struct {
	ctx context.Context

	conn  net.Conn
	conns map[string]*Target
	tun   *taptun.Tun

	lock sync.RWMutex
}

func NewTunnel(ctx context.Context, target string) (*Tunnel, error) {
	var c net.Conn
	tun, err := taptun.NewTun("")
	if err != nil {
		return nil, fmt.Errorf("cannot create tun %q: %s", tun, err)
	}
	fmt.Printf("created %q\n", tun)
	if target != "" {
		c, err = net.Dial("tcp", target)
		if err != nil {
			return nil, err
		}
	}
	return &Tunnel{
		ctx:   ctx,
		conn:  c,
		conns: map[string]*Target{},
		tun:   tun,
	}, nil
}

func (this *Tunnel) HandleTun() {
	go this.handleTun()
}

func (this *Tunnel) RegisterServer(ipNet net.IPNet, target string) error {
	key := ipNet
	key.IP = BroadcastAddress(ipNet)
	ipNet.Network()

	for _, t := range this.conns {
		if t.cidr.Contains(key.IP) {
			return nil
		}
	}
	c, err := net.Dial("tcp", target)
	if err != nil {
		return err
	}
	this.conns[key.String()] = &Target{c, key, target}
	go this.handleCon(c)
	return nil
}

func (this *Tunnel) RegisterClient(ipNet net.IPNet, c net.Conn, target string) error {
	key := ipNet
	key.IP = BroadcastAddress(ipNet)

	this.conns[key.String()] = &Target{c, key, target}
	go this.handleCon(c)
	return nil
}

func (this *Tunnel) HandleClient(c net.Conn) error {
	go this.handleCon(c)
	return nil
}

func (this *Tunnel) FindConnection(packet []byte) net.Conn {
	this.lock.RLock()
	defer this.lock.RUnlock()
	if len(this.conns) > 0 {
		vers := int(packet[0]) >> 4
		if vers == ipv4.Version {
			header, err := ipv4.ParseHeader(packet)
			if err != nil {
				fmt.Printf("err: %s\n", err)
			} else {
				fmt.Printf("ipv4[%d]: (%d) hdr: %d, total: %d, prot: %d,  %s->%s\n", header.Version, len(packet), header.Len, header.TotalLen, header.Protocol, header.Src, header.Dst)
			}
			for _, t := range this.conns {
				if t.cidr.Contains(header.Dst) {
					return t.conn
				}
			}
		} else {
			fmt.Printf("drop unknown packet (type %d)\n", vers)
			return nil
		}
	}
	return this.conn
}

func (this *Tunnel) handleTun() error {
	var buffer [BufferSize]byte
	bytes := buffer[:]
	for {
		n, err := this.tun.Read(bytes)
		if n <= 0 || err != nil {
			fmt.Printf("END: %d bytes, err=%s\n", n, err)
			if n <= 0 {
				err = io.EOF
			}
			return err
		}
		packet := bytes[:n]
		conn := this.FindConnection(packet)
		if conn == nil {
			fmt.Printf("dropping packet\n")
		} else {
			err = this.WritePacketToConnection(conn, packet)
		}
		if err != nil {
			return err
		}
	}
}

func (this *Tunnel) handleCon(conn net.Conn) error {
	var buffer [BufferSize]byte
	bytes := buffer[:]
	for {
		n, err := this.ReadPacketFromConnection(conn, bytes)
		if n <= 0 || err != nil {
			fmt.Printf("END: %d bytes, err=%s\n", n, err)
			if n <= 0 {
				err = io.EOF
			}
			return err
		}
		o, err := this.tun.Write(bytes[:n])
		if err != nil {
			return err
		}
		if n != o {
			panic(fmt.Errorf("packet length %d, but written %d", n, o))
		}
	}
}

func (this *Tunnel) read(r io.Reader, data []byte) error {
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

func (this *Tunnel) write(w io.Writer, data []byte) error {
	start := 0
	for start == len(data) {
		n, err := w.Write(data[start:])
		if err != nil {
			return err
		}
		start += n
	}
	return nil
}

func (this *Tunnel) ReadPacketFromConnection(conn net.Conn, data []byte) (int, error) {
	lbuf := [2]byte{}
	err := this.read(conn, lbuf[:])

	if err != nil {
		return 0, err
	}

	length := NtoHs(lbuf[:])
	if int(length) > len(data) {
		return 0, fmt.Errorf("buffer too small (%d): packet size is %d", len(data), length)
	}
	return int(length), this.read(conn, data[0:length])
}

func (this *Tunnel) WritePacketToConnection(conn net.Conn, data []byte) error {
	if len(data) > 65535 {
		return fmt.Errorf("packet too large (%d)", len(data))
	}
	lbuf := HtoNs(uint16(len(data)))
	err := this.write(conn, lbuf)
	if err != nil {
		return err
	}
	return this.write(conn, data)
}
