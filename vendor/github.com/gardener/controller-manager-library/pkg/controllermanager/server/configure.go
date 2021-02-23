/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package server

import (
	"fmt"
	"time"

	"github.com/gardener/controller-manager-library/pkg/config"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/cluster"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/extension"
	"github.com/gardener/controller-manager-library/pkg/utils"
)

func OptionSourceCreator(proto config.OptionSource) extension.OptionSourceCreator {
	return extension.OptionSourceCreatorByExample(proto)
}

type _Definition struct {
	name                   string
	kind                   ServerKind
	serverport             int
	required_clusters      []string
	handlers               map[string]HandlerType
	configs                extension.OptionDefinitions
	configsources          extension.OptionSourceDefinitions
	activateExplicitly     bool
	allowSecretMaintenance bool
}

var _ Definition = &_Definition{}

func (this *_Definition) String() string {
	kind := ""
	if this.kind != "" {
		kind = string(this.kind) + " "
	}
	s := fmt.Sprintf("%s server %s:\n", kind, this.Name())
	s += fmt.Sprintf("  server-port: %d\n", this.ServerPort())
	s += fmt.Sprintf("  clusters:    %s\n", utils.Strings(this.RequiredClusters()...))

	return s
}

func (this *_Definition) Name() string {
	return this.name
}

func (this *_Definition) Cluster() string {
	if len(this.required_clusters) == 0 {
		return ""
	}
	return this.required_clusters[0]
}
func (this *_Definition) Kind() ServerKind {
	return this.kind
}

func (this *_Definition) ServerPort() int {
	return this.serverport
}

func (this *_Definition) RequiredClusters() []string {
	if len(this.required_clusters) > 0 {
		return this.required_clusters
	}
	return []string{cluster.DEFAULT}
}

func (this *_Definition) Handlers() map[string]HandlerType {
	regs := map[string]HandlerType{}
	for p, r := range this.handlers {
		regs[p] = r
	}
	return regs
}

func (this *_Definition) ConfigOptions() extension.OptionDefinitions {
	return this.configs.Copy()
}

func (this *_Definition) ConfigOptionSources() extension.OptionSourceDefinitions {
	return this.configsources.Copy()
}

func (this *_Definition) ActivateExplicitly() bool {
	return this.activateExplicitly
}

func (this *_Definition) AllowSecretMaintenance() bool {
	return this.allowSecretMaintenance
}

////////////////////////////////////////////////////////////////////////////////
// Configuration
////////////////////////////////////////////////////////////////////////////////

type ConfigurationModifier func(c Configuration) Configuration

type Configuration struct {
	settings _Definition
	configState
}

type configState struct {
	previous *configState
}

func (this *configState) pushState() {
	save := *this
	this.previous = &save
}

func Configure(name string) Configuration {
	return Configuration{
		settings: _Definition{
			name:          name,
			serverport:    8081,
			configs:       extension.OptionDefinitions{},
			configsources: extension.OptionSourceDefinitions{},
		},
		configState: configState{},
	}
}

func (this Configuration) With(modifier ...ConfigurationModifier) Configuration {
	save := this.configState
	result := this
	for _, m := range modifier {
		result = m(result)
	}
	result.configState = save
	return result
}

func (this Configuration) Restore() Configuration {
	if &this.configState != nil {
		this.configState = *this.configState.previous
	}
	return this
}

func (this Configuration) Name(name string) Configuration {
	this.settings.name = name
	return this
}

func (this Configuration) TLS(tls bool) Configuration {
	if tls {
		this.settings.kind = HTTPS
	} else {
		this.settings.kind = HTTP
	}
	return this
}

func (this Configuration) AllowSecretMaintenance(b bool) Configuration {
	this.settings.allowSecretMaintenance = b
	return this
}

func (this Configuration) Cluster(name string) Configuration {
	if name == "" {
		name = cluster.DEFAULT
	}
	for _, n := range this.settings.required_clusters {
		if n == name {
			return this
		}
	}
	this.settings.required_clusters = append([]string{}, this.settings.required_clusters...)
	this.settings.required_clusters = append(this.settings.required_clusters, name)
	return this
}

func (this Configuration) Port(port int) Configuration {
	this.settings.serverport = port
	return this
}

func (this Configuration) RegisterHandler(name string, handler HandlerType) Configuration {
	this.settings.handlers = this.settings.Handlers()
	this.settings.handlers[name] = handler
	return this
}

func (this Configuration) StringOption(name string, desc string) Configuration {
	return this.addOption(name, config.StringOption, "", desc)
}
func (this Configuration) DefaultedStringOption(name, def string, desc string) Configuration {
	return this.addOption(name, config.StringOption, def, desc)
}

func (this Configuration) StringArrayOption(name string, desc string) Configuration {
	return this.addOption(name, config.StringArrayOption, nil, desc)
}
func (this Configuration) DefaultedStringArrayOption(name string, def []string, desc string) Configuration {
	return this.addOption(name, config.StringArrayOption, def, desc)
}

func (this Configuration) IntOption(name string, desc string) Configuration {
	return this.addOption(name, config.IntOption, 0, desc)
}
func (this Configuration) DefaultedIntOption(name string, def int, desc string) Configuration {
	return this.addOption(name, config.IntOption, def, desc)
}

func (this Configuration) BoolOption(name string, desc string) Configuration {
	return this.addOption(name, config.BoolOption, false, desc)
}
func (this Configuration) DefaultedBoolOption(name string, def bool, desc string) Configuration {
	return this.addOption(name, config.BoolOption, def, desc)
}

func (this Configuration) DurationOption(name string, desc string) Configuration {
	return this.addOption(name, config.DurationOption, time.Duration(0), desc)
}
func (this Configuration) DefaultedDurationOption(name string, def time.Duration, desc string) Configuration {
	return this.addOption(name, config.DurationOption, def, desc)
}

func (this Configuration) addOption(name string, t config.OptionType, def interface{}, desc string) Configuration {
	if this.settings.configs[name] != nil {
		panic(fmt.Sprintf("option %q already defined", name))
	}
	this.settings.configs[name] = extension.NewOptionDefinition(name, t, def, desc)
	return this
}

func (this Configuration) OptionSource(name string, creator extension.OptionSourceCreator) Configuration {
	if this.settings.configsources[name] != nil {
		panic(fmt.Sprintf("option source %q already defined", name))
	}
	this.settings.configsources[name] = extension.NewOptionSourceDefinition(name, creator)
	return this
}

func (this Configuration) OptionsByExample(name string, proto config.OptionSource) Configuration {
	if this.settings.configsources[name] != nil {
		panic(fmt.Sprintf("option source %q already defined", name))
	}
	this.settings.configsources[name] = extension.NewOptionSourceDefinition(name, OptionSourceCreator(proto))
	return this
}

func (this Configuration) ActivateExplicitly() Configuration {
	this.settings.activateExplicitly = true
	return this
}

func (this Configuration) Definition() Definition {
	return &this.settings
}

func (this Configuration) RegisterAt(registry RegistrationInterface) error {
	return registry.Register(this)
}

func (this Configuration) MustRegisterAt(registry RegistrationInterface) Configuration {
	registry.MustRegister(this)
	return this
}

func (this Configuration) Register() error {
	return registry.Register(this)
}

func (this Configuration) MustRegister() Configuration {
	registry.MustRegister(this)
	return this
}
