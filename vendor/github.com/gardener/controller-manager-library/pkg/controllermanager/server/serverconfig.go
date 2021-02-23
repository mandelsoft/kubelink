/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package server

import (
	"fmt"

	"github.com/gardener/controller-manager-library/pkg/config"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/cert"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/cluster"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/extension"
	areacfg "github.com/gardener/controller-manager-library/pkg/controllermanager/server/config"
)

const SERVER_SET_PREFIX = "server."

type ServerConfig struct {
	cert.CertConfig
	config.OptionSet
	ServerPort     int
	UseTLS         bool
	MaintainSecret bool
}

const PORT_OPTION = "server-port"
const TLS_OPTION = "use-tls"
const MAINTAIN_OPTION = "maintain-secret"

func NewServerConfig(name string) *ServerConfig {
	return &ServerConfig{
		CertConfig: *cert.NewCertConfig2(name, "", "", "kubernetes"),
		OptionSet: config.NewSharedOptionSet(name, name, func(desc string) string {
			return fmt.Sprintf("%s of server %s", desc, name)
		}),
	}
}

func (this *ServerConfig) AddOptionsToSet(set config.OptionSet) {
	this.OptionSet.AddOptionsToSet(set)
}

func (this *ServerConfig) Evaluate() error {
	return this.OptionSet.Evaluate()
}

func (this *ServerConfig) Reconfigure(def Definition) (Definition, error) {
	kind := def.Kind()
	clusters := def.RequiredClusters()
	mod := false

	if this.UseTLS != (def.Kind() == HTTPS) {
		mod = true
		if this.UseTLS {
			kind = HTTPS
		} else {
			kind = HTTP
		}
	}
	if kind == HTTPS && len(clusters) == 0 {
		mod = true
		clusters = []string{cluster.DEFAULT}
	}
	if mod {
		def = &_Definition{
			name:               def.Name(),
			kind:               kind,
			required_clusters:  clusters,
			serverport:         def.ServerPort(),
			handlers:           def.Handlers(),
			configs:            def.ConfigOptions(),
			configsources:      def.ConfigOptionSources(),
			activateExplicitly: def.ActivateExplicitly(),
		}
	}

	if def.Kind() == HTTPS {
		if this.Secret == "" && this.CertFile == "" {
			if !this.CertConfig.IsSecretMaintenanceDisabled() {
				this.Secret = def.Name()
				this.MaintainSecret = true
			} else {
				return def, fmt.Errorf("server certificate file or secret name required for HTTPS server")
			}
		}
		if this.Secret != "" && this.CertFile != "" {
			return def, fmt.Errorf("only one of server certificate file or secret name possible")
		}

		if this.Secret != "" {
			if this.MaintainSecret && this.CommonName == "" {
				this.CommonName = def.Name()
			}
			if this.MaintainSecret {
				if len(this.Hostnames) == 0 && this.Service == "" {
					return def, fmt.Errorf("server requires at least service name or hostname")
				}
				if len(this.Hostnames) > 1 {
					return def, fmt.Errorf("server requires only one hostname")
				}
			}
		}
		if this.CertFile != "" && this.KeyFile == "" {
			return def, fmt.Errorf("specifying server certficate require key file, also")
		}
	}
	return def, nil
}

func (this *_Definitions) ExtendConfig(cfg *areacfg.Config) {

	for name, def := range this.definitions {
		ccfg := NewServerConfig(name)
		if !def.AllowSecretMaintenance() {
			ccfg.DisableSecretMaintenance()
		}
		cfg.AddSource(name, ccfg)

		set := ccfg.OptionSet

		ccfg.CertConfig.AddOptionsToSet(set)
		set.AddIntOption(&ccfg.ServerPort, PORT_OPTION, "", def.ServerPort(), "server port")
		set.AddBoolOption(&ccfg.UseTLS, TLS_OPTION, "", def.Kind() == HTTPS, "use tls (https)")
		if def.AllowSecretMaintenance() {
			set.AddBoolOption(&ccfg.MaintainSecret, MAINTAIN_OPTION, "", false, "maintain tls secret")
		}
		extension.AddElementConfigDefinitionToSet(def, SERVER_SET_PREFIX, set)
	}
}
