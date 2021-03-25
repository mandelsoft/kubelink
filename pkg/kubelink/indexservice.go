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

package kubelink

import (
	"net"
	"sync"
)

type ServiceIndex struct {
	lock   sync.RWMutex
	byKey  map[string]*Service
	byAddr map[string]*Service
}

func NewServiceIndex() *ServiceIndex {
	return &ServiceIndex{
		byKey:  map[string]*Service{},
		byAddr: map[string]*Service{},
	}
}

func (this *ServiceIndex) Add(svc *Service) {
	this.lock.Lock()
	defer this.lock.Unlock()

	this.remove(svc.Key)

	this.byKey[svc.Key] = svc
	if svc.Address != nil {
		this.byAddr[svc.Address.String()] = svc
	}
}

func (this *ServiceIndex) Remove(key string) {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.remove(key)
}

func (this *ServiceIndex) remove(key string) *Service {
	old := this.byKey[key]
	if old == nil {
		return old
	}
	if old.Address != nil {
		delete(this.byAddr, old.Address.String())
	}
	delete(this.byKey, key)
	return old
}

func (this *ServiceIndex) All() map[string]*Service {
	this.lock.RLock()
	defer this.lock.RUnlock()
	r := map[string]*Service{}
	for k, v := range this.byKey {
		r[k] = v
	}
	return r
}

func (this *ServiceIndex) ByKey(key string) *Service {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.byKey[key]
}

func (this *ServiceIndex) ByAddress(ip net.IP) *Service {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.byAddr[ip.String()]
}

func (this *ServiceIndex) Visit(visitor func(l *Service) bool) {
	this.lock.RLock()
	services := make([]*Service, len(this.byKey))
	i := 0
	for _, l := range this.byKey {
		services[i] = l
		i++
	}
	this.lock.RUnlock()
	for _, s := range services {
		if !visitor(s) {
			break
		}
	}
}
