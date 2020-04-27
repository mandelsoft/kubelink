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
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/vishvananda/netlink"
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
	mux.Infof("dialing for %s to %s", link.Name, link.Endpoint)
	conn, err := mux.certInfo.Dial(link.Endpoint)
	if err != nil {
		mux.Errorf("dialing failed: %s", err)
		return nil, err
	}

	t := &TunnelConnection{
		mux:            mux,
		clusterAddress: link.ClusterAddress,
		conn:           conn,
		remoteAddress:  conn.RemoteAddr().String(),
		handlers:       append(handlers[:0:0], handlers...),
	}
	netlink.Iptun{}
	go func() {
		defer t.mux.RemoveTunnel(t)
		mux.Infof("serving connection to %s", t.String())
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

func printConnState(log logger.LogContext, state tls.ConnectionState) {
	log.Info(">>>>>>>>>>>>>>>> State <<<<<<<<<<<<<<<<")
	log.Infof("Version: %x", state.Version)
	log.Infof("HandshakeComplete: %t", state.HandshakeComplete)
	log.Infof("DidResume: %t", state.DidResume)
	log.Infof("CipherSuite: %x", state.CipherSuite)
	log.Infof("NegotiatedProtocol: %s", state.NegotiatedProtocol)
	log.Infof("NegotiatedProtocolIsMutual: %t", state.NegotiatedProtocolIsMutual)

	log.Info("Certificate chain:")
	for i, cert := range state.PeerCertificates {
		subject := cert.Subject
		issuer := cert.Issuer
		log.Infof(" %d s:/C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s", i, subject.Country, subject.Province, subject.Locality, subject.Organization, subject.OrganizationalUnit, subject.CommonName)
		log.Infof("   i:/C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s", issuer.Country, issuer.Province, issuer.Locality, issuer.Organization, issuer.OrganizationalUnit, issuer.CommonName)
	}
	log.Info(">>>>>>>>>>>>>>>> State End <<<<<<<<<<<<<<<<")
}

////////////////////////////////////////////////////////////////////////////////

func (this *TunnelConnection) Close() error {
	return this.conn.Close()
}

func (this *TunnelConnection) Serve() error {
	var buffer [BufferSize]byte
	working := false
	log := this.mux.NewContext("remote", this.remoteAddress)
	for {
		n, err := this.ReadPacket(buffer[:])
		if n <= 0 || err != nil {
			if working {
				log.Infof("connection aborted: %d bytes, err=%s", n, err)
			}
			if n <= 0 {
				err = io.EOF
			}
			return err
		}
		if !working {
			log.Infof("serving connection")
			working = true
		}
		packet := buffer[:n]
		vers := int(packet[0]) >> 4
		if vers == ipv4.Version {
			header, err := ipv4.ParseHeader(packet)
			if err != nil {
				log.Errorf("err: %s", err)
			} else {
				log.Infof("receiving ipv4[%d]: (%d) hdr: %d, total: %d, prot: %d,  %s->%s\n",
					header.Version, len(packet), header.Len, header.TotalLen, header.Protocol, header.Src, header.Dst)
				if !this.mux.clusterCIDR.Contains(header.Src) {
					log.Warnf("  dropping packet because of non-matching source address [%s]", this.mux.clusterCIDR, header.Src)
					continue
				} else {
					if this.clusterAddress == nil {
						this.clusterAddress = header.Src
					} else {
						log.Warnf("  dropping packet because of non-matching source address [%s]", this.clusterAddress, header.Dst)
						continue
					}
				}
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
		o, err := this.mux.tun.Write(buffer[:n])
		if err != nil {
			log.Infof(" connection aborted: %s", err)
			return err
		}
		if n != o {
			panic(fmt.Errorf("packet length %d, but written %d", n, o))
		}
	}
}

func (this *TunnelConnection) read(r io.Reader, data []byte) error {
	start := 0
	for start < len(data) {
		n, err := r.Read(data[start:])
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.EOF
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
