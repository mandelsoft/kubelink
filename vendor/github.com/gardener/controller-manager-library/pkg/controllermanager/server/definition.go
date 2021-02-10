/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package server

import (
	"fmt"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/cluster"
	areacfg "github.com/gardener/controller-manager-library/pkg/controllermanager/server/config"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/server/groups"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/server/mappings"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/utils"
)

type Definitions interface {
	Get(name string) Definition
	Size() int
	Names() utils.StringSet
	Groups() groups.Definitions
	GetMappingsFor(name string) (mappings.Definition, error)
	DetermineRequestedClusters(cfg *areacfg.Config, clusters cluster.Definitions, regs Registrations) (utils.StringSet, error)
	Registrations(names ...string) (Registrations, error)
	ExtendConfig(cfg *areacfg.Config)
}

func (this *_Definitions) Size() int {
	return len(this.definitions)
}

func (this *_Definitions) Groups() groups.Definitions {
	return this.groups
}

func (this *_Definitions) Names() utils.StringSet {
	set := utils.StringSet{}
	for n := range this.definitions {
		set.Add(n)
	}
	return set
}

func (this *_Definitions) GetMappingsFor(name string) (mappings.Definition, error) {
	return this.mappings.GetEffective(name, this.groups)
}

func (this *_Definitions) DetermineRequestedClusters(cfg *areacfg.Config, cdefs cluster.Definitions, regs Registrations) (_clusters utils.StringSet, _err error) {
	server_names := regs.Names()
	this.lock.RLock()
	defer this.lock.RUnlock()

	clusters := utils.StringSet{}
	logger.Infof("determining required clusters:")
	logger.Infof("  found mappings: %s", this.mappings)
	for n := range server_names {
		def := this.definitions[n]
		if def == nil {
			return nil, fmt.Errorf("server %q not definied", n)
		}

		scfg := cfg.GetSource(n).(*ServerConfig)
		var err error
		def, err = scfg.Reconfigure(def)
		if err != nil {
			return nil, fmt.Errorf("configuration error for server %s: %s", def.Name(), err)
		}
		regs[n] = def

		names := cluster.Canonical(def.RequiredClusters())
		if len(names) > 0 {
			cmp, err := this.GetMappingsFor(def.Name())
			if err != nil {
				return nil, err
			}

			logger.Infof("  for server %s:", n)
			logger.Infof("     found mappings %s", cmp)
			logger.Infof("     logical clusters %s", utils.Strings(names...))

			set, _, found, err := mappings.DetermineClusterMappings(cdefs, cmp, names...)
			if err != nil {
				return nil, fmt.Errorf("controller %q %s", def.Name(), err)
			}
			clusters.AddSet(set)
			logger.Infof("  mapped to %s", utils.Strings(found...))
		}
	}
	return clusters, nil
}

func (this *_Definitions) Registrations(names ...string) (Registrations, error) {
	this.lock.RLock()
	defer this.lock.RUnlock()
	var r = Registrations{}

	if len(names) == 0 {
		r = this.definitions.Copy()
	} else {
		for _, name := range names {
			def := this.definitions[name]
			if def == nil {
				return nil, fmt.Errorf("webhook %q not found", name)
			}
			r[name] = def
		}
	}
	return r, nil
}
