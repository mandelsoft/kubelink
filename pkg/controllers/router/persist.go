/*
 * Copyright 2021 Mandelsoft. All rights reserved.
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

package router

import (
	"io/ioutil"
	"os"
	"strings"

	"github.com/gardener/controller-manager-library/pkg/logger"

	"github.com/mandelsoft/kubelink/pkg/tcp"
)

func ReadRoutes(logger logger.LogContext, file string) (tcp.CIDRList, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Infof("file %s not found", file)
			return nil, nil
		}
		return nil, err
	}
	r := tcp.CIDRList{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cidr, err := tcp.ParseIPCIDR(line)
		if err != nil {
			logger.Errorf("cannot parse route cidr %q: %s", line, err)
		} else {
			r = append(r, cidr)
		}
	}
	return r, nil
}

func WriteRoutes(file string, list tcp.CIDRList) error {
	fd, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer fd.Close()
	for _, cidr := range list {
		_, err = fd.WriteString(cidr.String() + "\n")
		if err != nil {
			return err
		}
	}
	return nil
}
