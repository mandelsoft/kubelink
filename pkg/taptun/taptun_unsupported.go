// +build !linux,!freebsd,!darwin

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
	"fmt"
	"os"
)

func createInterface(flags uint16) (string, *os.File, error) {
	return "", nil, fmt.Errorf("%s is unsupported", runtime.GOOS)
}

func destroyInterface(name string) error {
	return fmt.Errorf("%s is unsupported", runtime.GOOS)
}

func openTun(_ string) (string, *os.File, error) {
	return createInterface(0)
}

func openTap(_ string) (string, *os.File, error) {
	return createInterface(0)
}
