/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package server

import (
	"fmt"
	"sync"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/server/groups"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/server/mappings"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/utils"
)

///////////////////////////////////////////////////////////////////////////////
// controller Registrations
///////////////////////////////////////////////////////////////////////////////

type Registrations map[string]Definition

func (this Registrations) Copy() Registrations {
	r := Registrations{}
	for n, def := range this {
		r[n] = def
	}
	return r
}

func (this Registrations) Names() utils.StringSet {
	r := utils.StringSet{}
	for n := range this {
		r.Add(n)
	}
	return r
}

type Registerable interface {
	Definition() Definition
}

type RegistrationInterface interface {
	Register(reg Registerable, group ...string) error
	MustRegister(reg Registerable, group ...string) RegistrationInterface
}

type Registry interface {
	RegistrationInterface
	GetDefinitions() Definitions
}

type _Definitions struct {
	lock        sync.RWMutex
	definitions Registrations
	groups      groups.Definitions
	mappings    mappings.Definitions
}

type _Registry struct {
	*_Definitions
	groups   groups.Registry
	mappings mappings.Registry
}

var _ Definition = &_Definition{}
var _ Definitions = &_Definitions{}

func NewRegistry() Registry {
	return newRegistry(groups.NewRegistry(), mappings.NewRegistry())
}

func newRegistry(groups groups.Registry, mappings mappings.Registry) Registry {
	return &_Registry{_Definitions: &_Definitions{definitions: Registrations{}}, groups: groups, mappings: mappings}
}

func DefaultDefinitions() Definitions {
	return registry.GetDefinitions()
}

func DefaultRegistry() Registry {
	return registry
}

////////////////////////////////////////////////////////////////////////////////

var _ Registry = &_Registry{}

func (this *_Registry) Register(reg Registerable, grps ...string) error {
	def := reg.Definition()
	if def == nil {
		return fmt.Errorf("no Definition found")
	}
	this.lock.Lock()
	defer this.lock.Unlock()

	if d, ok := this.definitions[def.Name()]; ok && d != def {
		return fmt.Errorf("multiple registrations of server %q", def.Name())
	}
	logger.Infof("Registering server %s", def.Name())

	if len(grps) == 0 {
		grps = []string{groups.DEFAULT, string(def.Kind())}
	} else {
		grps = append(grps, string(def.Kind()))
	}
	for _, g := range grps {
		err := this.addToGroup(def, g)
		if err != nil {
			return err
		}
	}
	this.definitions[def.Name()] = def
	return nil
}

func (this *_Registry) MustRegister(reg Registerable, group ...string) RegistrationInterface {
	err := this.Register(reg, group...)
	if err != nil {
		panic(err)
	}
	return this
}

////////////////////////////////////////////////////////////////////////////////

func (this *_Registry) GetDefinitions() Definitions {
	defs := Registrations{}
	for k, v := range this.definitions {
		defs[k] = v
	}
	return &_Definitions{
		definitions: defs,
		groups:      this.groups.GetDefinitions(),
		mappings:    this.mappings.GetDefinitions(),
	}
}

func (this *_Definitions) Get(name string) Definition {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.definitions[name]
}

func (this *_Definition) Definition() Definition {
	return this
}

///////////////////////////////////////////////////////////////////////////////

var registry = newRegistry(groups.DefaultRegistry(), mappings.DefaultRegistry())

func (this *_Registry) addToGroup(def Definition, name string) error {
	grp, err := this.groups.RegisterGroup(name)
	if err != nil {
		return err
	}
	if def.ActivateExplicitly() {
		grp.ActivateExplicitly(def.Name())
	}
	return grp.Members(def.Name())
}

///////////////////////////////////////////////////////////////////////////////

func Register(reg Registerable, group ...string) error {
	return registry.Register(reg, group...)
}

func MustRegister(reg Registerable, group ...string) RegistrationInterface {
	return registry.MustRegister(reg, group...)
}
