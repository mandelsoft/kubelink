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
	"strings"

	"github.com/mandelsoft/kubelink/pkg/kubelink"
)

func init() {
	RegisterExtension(EXT_DNS, &DNSExtensionHandler{})
}

type DNSExtension kubelink.LinkAccessInfo

var _ ConnectionHelloExtension = &DNSExtension{}

func (this *DNSExtension) Id() byte {
	return EXT_DNS
}

func (this *DNSExtension) Data() []byte {
	return append(append([]byte(this.Token), 0), []byte(this.CACert)...)
}

type DNSExtensionHandler struct{}

var _ ConnectionHelloExtensionHandler = &DNSExtensionHandler{}

func (this *DNSExtensionHandler) Parse(id byte, data []byte) (ConnectionHelloExtension, error) {
	if id != EXT_DNS {
		return nil, fmt.Errorf("invalid extension %d for DNS", id)
	}
	s := strings.Split(string(data), "\000")
	if len(s) == 1 {
		return &DNSExtension{s[0], ""}, nil
	}
	return &DNSExtension{s[0], s[1]}, nil
}

func (this *DNSExtensionHandler) Add(hello *ConnectionHello, mux *Mux) {
	if mux.connectionHandler != nil {
		access := mux.connectionHandler.GetAccess()
		if access.Token != "" {
			ext := DNSExtension(access)
			hello.Extensions[EXT_DNS] = &ext
		}
	}
}
