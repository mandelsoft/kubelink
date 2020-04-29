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
	"golang.org/x/net/ipv4"

	"github.com/mandelsoft/kubelink/pkg/kubelink"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

const BufferSize = 17000

type ConnectionHelloExtension interface {
	Id() byte
	Data() []byte
}

type ConnectionHello struct {
	ConnectionHelloHeader
	Extensions map[byte]ConnectionHelloExtension
	Raw        map[byte][]byte
}

func NewConnectionHello() *ConnectionHello {
	return &ConnectionHello{
		Extensions: map[byte]ConnectionHelloExtension{},
		Raw:        map[byte][]byte{},
	}
}
func ParseConnectionHello(header *ConnectionHelloHeader, data []byte) (*ConnectionHello, error) {
	if int(header.GetExtensionLength()) != len(data) {
		return nil, fmt.Errorf("data too short: required %d, but found %d", int(header.GetExtensionLength()), len(data))
	}
	hello := NewConnectionHello()
	hello.ConnectionHelloHeader = *header
	start := 0

	for start < len(data) {
		if len(data)-start < 3 {
			return nil, fmt.Errorf("data too short: next extesion requires at least 3 bytes, but found %d", len(data)-start)
		}
		id := data[start]
		el := int(tcp.NtoHs(data[start+1:]))
		if len(data)-start-3 < el {
			return nil, fmt.Errorf("data too short: next extesion %d requires at least %d bytes, but found %d", id, el, len(data)-start-3)
		}
		ext := data[start+3 : start+3+el]
		hello.Raw[id] = ext
		start = start + 3 + el
	}
	return hello, nil
}

func (this *ConnectionHello) Data() []byte {
	var ext []byte

	for _, e := range this.Extensions {
		this.Raw[e.Id()] = e.Data()
	}
	for id, data := range this.Raw {
		ext = append(ext, id)
		ext = append(ext, tcp.HtoNs(uint16(len(data)))...)
		ext = append(ext, data...)
	}
	this.ConnectionHelloHeader.SetExtensionLength(uint16(len(ext)))
	return append(this.ConnectionHelloHeader[:], ext...)
}

type ConnectionHelloHeader [net.IPv6len * 5]byte

func (this *ConnectionHelloHeader) setAddress(start int, ip net.IP) {
	copy(this[start:start+net.IPv6len], ip.To16())
}

func (this *ConnectionHelloHeader) setCIDR(start int, cidr *net.IPNet) {
	this.setAddress(start, cidr.IP)
	copy(this[start+net.IPv6len:start+net.IPv6len*2], net.IP(cidr.Mask).To16())
}

func (this *ConnectionHelloHeader) getAddress(start int) net.IP {
	return net.IP(this[start : start+net.IPv6len])
}

func (this *ConnectionHelloHeader) getCIDR(start int) *net.IPNet {
	ip := this.getAddress(start)
	if ip.To4() == nil {
		return &net.IPNet{
			IP:   ip,
			Mask: net.IPMask(this[start+net.IPv6len : start+net.IPv6len*2]),
		}

	} else {
		return &net.IPNet{
			IP:   ip,
			Mask: net.IPMask(this[start+net.IPv6len+net.IPv6len-net.IPv4len : start+net.IPv6len*2]),
		}
	}
}

func (this *ConnectionHelloHeader) SetExtensionLength(len uint16) {
	copy(this[net.IPv6len*5-2:], tcp.HtoNs(len))
}

func (this *ConnectionHelloHeader) GetExtensionLength() uint16 {
	return tcp.NtoHs(this[net.IPv6len*5-2:])
}

func (this *ConnectionHelloHeader) SetPort(port uint16) {
	copy(this[net.IPv6len*4:], tcp.HtoNs(port))
}

func (this *ConnectionHelloHeader) GetPort() uint16 {
	return tcp.NtoHs(this[net.IPv6len*4:])
}

func (this *ConnectionHelloHeader) SetClusterAddress(ip net.IP) {
	this.setAddress(0, ip)
}

func (this *ConnectionHelloHeader) SetClusterCIDR(cidr *net.IPNet) {
	this.setCIDR(0, cidr)
}

func (this *ConnectionHelloHeader) GetClusterAddress() net.IP {
	return this.getAddress(0)
}

func (this *ConnectionHelloHeader) GetClusterCIDR() *net.IPNet {
	return this.getCIDR(0)
}

func (this *ConnectionHelloHeader) SetCIDR(cidr *net.IPNet) {
	this.setCIDR(net.IPv6len*2, cidr)
}

func (this *ConnectionHelloHeader) GetCIDR() *net.IPNet {
	return this.getCIDR(net.IPv6len * 2)
}

func to16Mask(mask net.IPMask) net.IPMask {
	if len(mask) == net.IPv6len {
		return mask
	}
	if len(mask) == net.IPv4len {
		r := net.CIDRMask((net.IPv6len-net.IPv4len)*8, net.IPv6len)
		copy(r[(net.IPv6len-net.IPv4len)*8:], mask)
		return r
	}
	return nil
}

////////////////////////////////////////////////////////////////////////////////

type ConnectionFailHandler interface {
	Notify(*TunnelConnection, error)
}

type TunnelConnection struct {
	logger.LogContext
	lock          sync.RWMutex
	mux           *Mux
	conn          net.Conn
	clusterCIDR   *net.IPNet
	remoteAddress string
	handlers      []ConnectionFailHandler
}

func NewTunnelConnection(mux *Mux, conn net.Conn, link *kubelink.Link, handlers ...ConnectionFailHandler) (*TunnelConnection, *ConnectionHello, error) {
	remote := conn.RemoteAddr().String()
	t := &TunnelConnection{
		LogContext:    mux.NewContext("source", remote),
		mux:           mux,
		conn:          conn,
		remoteAddress: remote,
		handlers:      append(handlers[:0:0], handlers...),
	}
	if link != nil {
		t.clusterCIDR = link.ClusterAddress
	}

	hello, err := t.handshake()
	if err != nil {
		return nil, nil, err
	}
	if hello != nil {
		cidr := hello.GetClusterCIDR()
		if !net.IPv6zero.Equal(cidr.IP) {
			if link != nil {
				if !link.ClusterAddress.IP.Equal(cidr.IP) {
					return nil, hello, fmt.Errorf("cluster address mismatch: got %s but expected %s", cidr.IP, link.ClusterAddress.IP)
				}
			}
			if !cidr.Contains(mux.clusterAddr.IP) {
				// obsolete when we support unidirectional connections
				return nil, hello, fmt.Errorf("cluster address mismatch: own address %s not in foreign range", mux.clusterAddr.IP, cidr)
			}
			if !mux.clusterAddr.Contains(cidr.IP) {
				return nil, hello, fmt.Errorf("cluster address mismatch: remote address %s not in local range", cidr.IP, mux.clusterAddr)
			}
		}
	}
	return t, hello, nil
}

func (this *TunnelConnection) String() string {
	return fmt.Sprintf("%s[%s]", this.clusterCIDR, this.remoteAddress)
}

func (this *TunnelConnection) RegisterStateHandler(handlers ...ConnectionFailHandler) {
	this.lock.Lock()
	defer this.lock.Unlock()

	this.handlers = append(this.handlers, handlers...)
}

func (this *TunnelConnection) notify(err error) {
	if err == io.EOF {
		return
	}
	this.mux.Notify(this, err)
	this.lock.RLock()
	defer this.lock.RUnlock()
	for _, h := range this.handlers {
		h.Notify(this, err)
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

func (this *TunnelConnection) writeHello(hello *ConnectionHello) error {
	data := hello.Data()
	return this.write(this.conn, data)
}

func (this *TunnelConnection) readHello() (*ConnectionHello, error) {
	var header ConnectionHelloHeader
	err := this.read(this.conn, header[:])
	if err != nil {
		return nil, err
	}
	len := header.GetExtensionLength()
	buf := make([]byte, len)
	err = this.read(this.conn, buf)
	if err != nil {
		return nil, err
	}
	return ParseConnectionHello(&header, buf)
}

func (this *TunnelConnection) handshake() (*ConnectionHello, error) {
	local := NewConnectionHello()
	local.SetClusterCIDR(this.mux.clusterAddr)
	local.SetPort(this.mux.port)
	if len(this.mux.local) > 0 {
		local.SetCIDR(&this.mux.local[0])
	}
	var werr error
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		werr = this.writeHello(local)
	}()

	remote, rerr := this.readHello()
	wg.Wait()
	if rerr != nil {
		return nil, fmt.Errorf("cannot finish connection handshake: %s", rerr)
	}
	if werr != nil {
		return nil, fmt.Errorf("cannot finish connection handshake: %s", werr)
	}
	this.Infof("REMOTE SIDE: cluster %s, net: %s port: %d", remote.GetClusterCIDR(), remote.GetCIDR(), remote.GetPort())
	return remote, nil
}

func (this *TunnelConnection) Serve() error {
	err := this.serve()
	this.notify(err)
	return err
}

func (this *TunnelConnection) serve() error {
	var buffer [BufferSize]byte
	for {
		n, err := this.ReadPacket(buffer[:])
		if n < 0 || err != nil {
			this.Infof("connection aborted: %d bytes, err=%s", n, err)
			if n <= 0 {
				err = io.EOF
			}
			return err
		}
		if n == 0 {
			continue
		}
		packet := buffer[:n]
		vers := int(packet[0]) >> 4
		if vers == ipv4.Version {
			header, err := ipv4.ParseHeader(packet)
			if err != nil {
				this.Errorf("err: %s", err)
				continue
			} else {
				this.Infof("receiving ipv4[%d]: (%d) hdr: %d, total: %d, prot: %d,  %s->%s\n",
					header.Version, len(packet), header.Len, header.TotalLen, header.Protocol, header.Src, header.Dst)
				if this.mux.clusterAddr.Contains(header.Src) {
					if len(this.mux.local) > 0 {
						found := false
						for _, local := range this.mux.local {
							if local.Contains(header.Dst) {
								found = true
								break
							}
						}
						if !found {
							this.Warnf("  dropping packet because of non-matching destination address [%s]", this.mux.clusterAddr, header.Src)
							continue
						}
					}
				} else {
					if !header.Dst.Equal(this.mux.clusterAddr.IP) {
						this.Warnf("  dropping packet because of non-matching destination address [%s<>%s]", this.mux.clusterAddr.IP, header.Dst)
						continue
					}
				}
			}
		}
		o, err := this.mux.tun.Write(buffer[:n])
		if err != nil {
			if err != io.EOF {
				this.Infof("connection aborted: cannot write tun: %s", err)
			}
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
		if n < 0 {
			return io.EOF
		}
		start += n
		if start < len(data) {
			this.Infof("read next chunk %d", start)
		}
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
		if start < len(data) {
			this.Infof("write next chunk %d", start)
		}
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
