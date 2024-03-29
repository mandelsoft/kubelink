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

package taptun

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

type ifreq struct {
	name [syscall.IFNAMSIZ]byte
	_    [16]byte
}

func interfaceName(fd uintptr) (string, error) {
	var name [syscall.IFNAMSIZ]byte

	arg := fiodgnameArg{length: syscall.IFNAMSIZ, buf: unsafe.Pointer(&name)}
	if err := ioctl(fd, FIODGNAME, unsafe.Pointer(&arg)); err != nil {
		return "", err
	}
	return cstringToGoString(name[:]), nil
}

type ifrenameArg struct {
	name [syscall.IFNAMSIZ]byte
	data uintptr
}

func renameInterface(from string, to string) error {
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer func() {
		syscall.Close(s)
	}()

	var ifr ifrenameArg
	copy(ifr.name[:], []byte(from))

	var toName [syscall.IFNAMSIZ]byte
	copy(toName[:], []byte(to))
	ifr.data = uintptr(unsafe.Pointer(&toName))

	return ioctl(uintptr(s), syscall.SIOCSIFNAME, unsafe.Pointer(&ifr))
}

func createInterface(clonefile string, name string) (string, *os.File, error) {
	// Last byte of name must be nil for C string, so name must be
	// short enough to allow that
	if len(name) > syscall.IFNAMSIZ-1 {
		return "", nil, errors.New("device name too long")
	}

	f, err := os.OpenFile(clonefile, os.O_RDWR, 0600)
	if err != nil {
		return "", nil, err
	}

	fd := f.Fd()
	ifname, err := interfaceName(fd)
	if err != nil {
		f.Close()
		return "", nil, err
	}

	// Interface renamed after creation if a name is specified
	if name != "" {
		if err := renameInterface(ifname, name); err != nil {
			return "", nil, err
		}
		ifname = name
	}

	return ifname, f, nil
}

func destroyInterface(name string) error {
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_IP)
	if err != nil {
		return err
	}
	defer syscall.Close(s)

	ifreq := ifreq{}
	copy(ifreq.name[:], []byte(name))

	return ioctl(uintptr(s), syscall.SIOCIFDESTROY, unsafe.Pointer(&ifreq))
}

func openTun(name string) (string, *os.File, error) {
	return createInterface("/dev/tun", name)
}

func openTap(name string) (string, *os.File, error) {
	return createInterface("/dev/tap", name)
}
