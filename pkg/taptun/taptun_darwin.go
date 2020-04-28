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
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// #cgo CFLAGS: -I./
// #include <taptun_darwin.h>
import "C"

type ifreq struct {
	name  [syscall.IFNAMSIZ]byte // c string
	flags uint16                 // c short
	_pad  [24 - unsafe.Sizeof(uint16(0))]byte
}

func createInterface(name string) (string, *os.File, error) {
	var fd, unit C.int
	var error *C.char
	C.osxtun_open(&fd, &unit, &error)
	if fd < 0 {
		return "", nil, errors.New(C.GoString(error))
	}
	tunName := fmt.Sprintf("utun%d", unit)
	return tunName, os.NewFile(uintptr(fd), tunName), nil
}

func destroyInterface(name string) error {
	return nil
}

func openTun(name string) (string, *os.File, error) {
	return createInterface(name)
}

func openTap(name string) (string, *os.File, error) {
	// not support yet
	return "", nil, errors.New("tap not support yet.")
}
