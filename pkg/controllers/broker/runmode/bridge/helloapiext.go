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

package bridge

import (
	"fmt"
	"strings"

	"github.com/mandelsoft/kubelink/pkg/kubelink"
)

func init() {
	RegisterExtension(EXT_APIACCESS, &APIExtensionHandler{})
}

type APIExtension kubelink.LinkAccessInfo

var _ ConnectionHelloExtension = &APIExtension{}

func (this *APIExtension) Id() byte {
	return EXT_APIACCESS
}

func (this *APIExtension) Data() []byte {
	d := append([]byte{}, append(append([]byte(this.Token), 0), []byte(this.CACert)...)...)
	return d
}

func (this *APIExtension) String() string {
	return ((*kubelink.LinkAccessInfo)(this)).String()
}

type APIExtensionHandler struct{}

var _ ConnectionHelloExtensionHandler = &APIExtensionHandler{}

func (this *APIExtensionHandler) Parse(id byte, data []byte) (ConnectionHelloExtension, error) {
	if id != EXT_APIACCESS {
		return nil, fmt.Errorf("invalid extension %d for API access", id)
	}
	s := strings.Split(string(data), "\000")
	if len(s) == 1 {
		return &APIExtension{Token: s[0], CACert: ""}, nil
	}
	return &APIExtension{Token: s[0], CACert: s[1]}, nil
}

func (this *APIExtensionHandler) Add(hello *ConnectionHello, mux *Mux) {
	if mux.connectionHandler != nil {
		access := mux.connectionHandler.GetAccess()
		if access.Token != "" {
			mux.Infof("adding access info %s", access)
			ext := APIExtension(access)
			hello.Extensions[EXT_APIACCESS] = &ext
		}
	}
}
