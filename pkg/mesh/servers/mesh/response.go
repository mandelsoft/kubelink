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

package mesh

import (
	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
)

type InfoResponse struct {
	Member *MemberInfo `json:"member,omitempty"`
	Error  string      `json:"error,omitempty"`
}

type MemberInfo struct {
	PeerInfo `json:",inline"`
	Peers    []PeerInfo `json:"peers,omitempty"`
}

type PeerInfo struct {
	Identity  string                `json:"identity,omitempty"`
	Address   string                `json:"address,omitempty"`
	PublicKey string                `json:"publicKey,omitempty"`
	Endpoint  string                `json:"endpoint,omitempty"`
	Gateway   string                `json:"gateway,omitempty"`
	Routes    []api.MeshMemberRoute `json:"routes,omitempty"`
}

func (this *PeerInfo) AddRoutes(routes ... api.MeshMemberRoute) {
	next:
	for _, r := range routes {
		for _, f := range this.Routes {
			if f.Equal(&r) {
				continue next
			}
		}
		this.Routes=append(this.Routes, r)
	}
}
