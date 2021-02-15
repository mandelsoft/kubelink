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

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Member interface {
	GetId() string
}

type member struct {
	id      string
	address *net.IPNet

	publicKey wgtypes.Key
}

var _ Member = &member{}

func (this *member) GetId() string {
	return this.id
}

func (this *member) GetAddress() *net.IPNet {
	r := *this.address
	return &r
}

func (this *member) GetPublicKey() wgtypes.Key {
	k, _ := wgtypes.NewKey(this.publicKey[:])
	return k
}
