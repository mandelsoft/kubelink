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
	"crypto/x509"
	"net"
	"sync"

	"github.com/gardener/controller-manager-library/pkg/resources"

	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
)

type Meshes interface {
	IsReady() bool
	SetReady()

	GetMeshByName(name resources.ObjectName) Mesh
	GetMeshByNamespace(name string) Mesh
	GetMeshById(id string) Mesh

	UpdateMesh(mesh resources.Object, ipam *resources.ClusterObjectKey, pool *x509.CertPool)
	DeleteByName(name resources.ObjectName)
}

func NewMeshs() Meshes {
	return &meshes{
		meshByName:      map[resources.ObjectName]*mesh{},
		meshByNamespace: map[string]*mesh{},
		meshById:        map[string]*mesh{},
	}
}

type meshes struct {
	lock            sync.Mutex
	ready           bool
	meshByName      map[resources.ObjectName]*mesh
	meshByNamespace map[string]*mesh
	meshById        map[string]*mesh
}

func (this *meshes) IsReady() bool {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.ready
}

func (this *meshes) SetReady() {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.ready = true
}

func (this *meshes) GetMeshByName(name resources.ObjectName) Mesh {
	this.lock.Lock()
	defer this.lock.Unlock()
	return ToMesh(this.meshByName[name])
}

func (this *meshes) GetMeshById(id string) Mesh {
	this.lock.Lock()
	defer this.lock.Unlock()
	return ToMesh(this.meshById[id])
}

func (this *meshes) GetMeshByNamespace(name string) Mesh {
	this.lock.Lock()
	defer this.lock.Unlock()
	return ToMesh(this.meshByNamespace[name])
}

func (this *meshes) UpdateMesh(obj resources.Object, ipam *resources.ClusterObjectKey, pool *x509.CertPool) {
	mesh := obj.Data().(*api.Mesh)
	this.lock.Lock()
	defer this.lock.Unlock()
	name := resources.NewObjectName(mesh.Namespace, mesh.Name)
	old := this.meshByName[name]

	_, cidr, _ := net.ParseCIDR(mesh.Spec.Network.CIDR)
	if old == nil {
		old = NewMesh(obj.ClusterKey(), mesh.Spec.Identity, mesh.Spec.Namespace, mesh.Spec.Domain, cidr)
		this.meshByName[name] = old
	} else {
		delete(this.meshById, mesh.Spec.Identity)
		delete(this.meshByNamespace, mesh.Spec.Namespace)
	}

	old.namespace = mesh.Spec.Namespace
	old.domain = mesh.Spec.Domain
	old.cidr = cidr
	old.id = mesh.Spec.Identity
	old.state = mesh.Status.State
	old.message = mesh.Status.Message
	old.ipam = ipam
	old.SetPool(pool)
	if mesh.Spec.Namespace != "" {
		this.meshByNamespace[mesh.Spec.Namespace] = old
	}
	this.meshById[old.id] = old
}

func (this *meshes) DeleteByName(name resources.ObjectName) {
	this.lock.Lock()
	defer this.lock.Unlock()

	old := this.meshByName[name]
	if old != nil {
		delete(this.meshByName, name)
		if this.meshById[old.id] == old {
			delete(this.meshById, old.id)
		}
		if this.meshByNamespace[old.namespace] == old {
			delete(this.meshByNamespace, old.namespace)
		}
	}
}
