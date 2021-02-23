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

package database

import (
	"net"
	"time"

	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/gardener/controller-manager-library/pkg/utils"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const EP_PUBLIC = "public"

type Member interface {
	GetId() string
	GetName() resources.ClusterObjectKey
	GetAddress() *net.IPNet
	GetPublicKey() *wgtypes.Key

	GetEndpoints() map[string]string
	GetGateway() resources.ObjectName
	GetRoutes() []Route
	GetServedMembers() utils.StringSet

	GetCreationTimestamp() time.Time
}

type member struct {
	name    resources.ClusterObjectKey
	id      string
	address *net.IPNet
	routes  []Route
	gateway resources.ObjectName
	endpoints map[string]string

	gatewayFor utils.StringSet
	publicKey  *wgtypes.Key
	created time.Time
}

var _ Member = &member{}

func NewMember(name resources.ClusterObjectKey, id string) *member {
	return &member{
		name:       name,
		id:         id,
		endpoints: map[string]string{},
		gatewayFor: utils.StringSet{},
	}
}

func ToMember(m *member) Member {
	if m == nil {
		return nil
	}
	return m
}

func (this *member) GetName() resources.ClusterObjectKey {
	return this.name
}

func (this *member) GetId() string {
	return this.id
}

func (this *member) GetAddress() *net.IPNet {
	if this.address == nil {
		return nil
	}
	r := *this.address
	return &r
}

func (this *member) GetRoutes() []Route {
	return this.routes
}

func (this *member) GetCreationTimestamp() time.Time {
	return this.created
}

func (this *member) GetEndpoints() map[string]string {
  r:=map[string]string{}
  for k, v := range this.endpoints {
  	r[k]=v
  }
  return r
}

func (this *member) GetGateway() resources.ObjectName {
	return this.gateway
}

func (this *member) GetServedMembers() utils.StringSet {
	return this.gatewayFor.Copy()
}

func (this *member) GetPublicKey() *wgtypes.Key {
	if this.publicKey == nil {
		return nil
	}
	k, _ := wgtypes.NewKey(this.publicKey[:])
	return &k
}


