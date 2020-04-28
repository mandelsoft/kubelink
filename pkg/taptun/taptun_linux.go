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
	"unsafe"

	"golang.org/x/sys/unix"
)

type ifreq struct {
	name  [unix.IFNAMSIZ]byte // c string
	flags uint16              // c short
	_pad  [24 - unsafe.Sizeof(uint16(0))]byte
}

func createInterface(flags uint16, name string) (string, *os.File, error) {
	// Last byte of name must be nil for C string, so name must be
	// short enough to allow that
	if len(name) > unix.IFNAMSIZ-1 {
		return "", nil, errors.New("device name too long")
	}

	fd, err := unix.Open("/dev/net/tun", os.O_RDWR, 0600)
	if err != nil {
		return "", nil, err
	}

	var nbuf [unix.IFNAMSIZ]byte
	copy(nbuf[:], []byte(name))

	ifr := ifreq{
		name:  nbuf,
		flags: flags,
	}
	if err := ioctl(uintptr(fd), unix.TUNSETIFF, unsafe.Pointer(&ifr)); err != nil {
		return "", nil, err
	}
	unix.SetNonblock(fd, true)
	return cstringToGoString(ifr.name[:]), os.NewFile(uintptr(fd), "/dev/net/tun"), nil
}

func destroyInterface(name string) error {
	return nil
}

func openTun(name string) (string, *os.File, error) {
	return createInterface(unix.IFF_TUN|unix.IFF_NO_PI, name)
}

func openTap(name string) (string, *os.File, error) {
	return createInterface(unix.IFF_TAP|unix.IFF_NO_PI, name)
}
