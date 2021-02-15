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
	"sync"
)

type Meshs interface {
	GetMeshById(id string) Mesh
	GetMeshByCidr(cidr *net.IPNet) Mesh
}

func NewMeshs() Meshs {
	return &meshs{
		meshById:   map[string]*mesh{},
		meshByCidr: map[string]*mesh{},
	}
}

type meshs struct {
	lock       sync.Mutex
	meshById   map[string]*mesh
	meshByCidr map[string]*mesh
}

func (this *meshs) GetMeshById(id string) Mesh {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.meshById[id]
}

func (this *meshs) GetMeshByCidr(cidr *net.IPNet) Mesh {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.meshByCidr[cidr.String()]
}
