/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

package server

import (
	"fmt"
	"net/http"

	"github.com/gardener/controller-manager-library/pkg/certmgmt"
	"github.com/gardener/controller-manager-library/pkg/certmgmt/secret"
	"github.com/gardener/controller-manager-library/pkg/certs"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/cluster"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/extension"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/server/handler"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/server/mappings"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/gardener/controller-manager-library/pkg/server"
	"github.com/gardener/controller-manager-library/pkg/utils"
)

type httpserver struct {
	extension.ElementBase
	extension.SharedAttributes

	definition  Definition
	env         Environment
	clusters    cluster.Clusters
	cluster     cluster.Interface
	server      *server.HTTPServer
	handlers    map[string]handler.Interface
	certificate certs.CertificateSource

	config *ServerConfig
}

func NewServer(env Environment, def Definition, cmp mappings.Definition) (*httpserver, error) {
	options := env.GetConfig().GetSource(def.Name()).(*ServerConfig)

	this := &httpserver{
		definition: def,
		config:     options,
		env:        env,
		handlers:   map[string]handler.Interface{},
	}

	this.ElementBase = extension.NewElementBase(env.GetContext(), ctx_server, this, def.Name(), SERVER_SET_PREFIX, options)
	this.SharedAttributes = extension.NewSharedAttributes(this.ElementBase)
	this.server = server.NewHTTPServer(this.GetContext(), this, def.Name())

	required := cluster.Canonical(def.RequiredClusters())
	if len(required) != 0 {
		clusters, err := mappings.MapClusters(env.GetClusters(), cmp, required...)
		if err != nil {
			return nil, err
		}
		this.Infof("  using clusters %+v: %s (selected from %s)", required, clusters, env.GetClusters())
		this.clusters = clusters
		this.cluster = clusters.GetCluster(required[0])
		if options.Secret != "" {
			this.Infof(" using secret %s", options.Secret)
		}
		if options.Service != "" {
			logger.Infof("  using service %s", options.Service)
		}
		if len(options.Hostnames) != 0 {
			logger.Infof("  using hostname %s", utils.Strings(options.Hostnames...))
		}
	}
	logger.Infof(" using port %d", options.ServerPort)
	return this, nil
}

func (this *httpserver) GetEnvironment() Environment {
	return this.env
}

func (this *httpserver) GetDefinition() Definition {
	return this.definition
}

func (this *httpserver) GetKind() ServerKind {
	return this.definition.Kind()
}

func (this *httpserver) GetClusterById(id string) cluster.Interface {
	return this.clusters.GetById(id)
}

func (this *httpserver) GetCluster(name string) cluster.Interface {
	if name == CLUSTER_MAIN || name == "" {
		return this.GetMainCluster()
	}
	return this.clusters.GetCluster(name)
}

func (this *httpserver) GetMainCluster() cluster.Interface {
	return this.cluster
}

func (this *httpserver) GetClusterAliases(eff string) utils.StringSet {
	return this.clusters.GetAliases(eff)
}

func (this *httpserver) GetEffectiveCluster(eff string) cluster.Interface {
	return this.clusters.GetEffective(eff)
}

func (this *httpserver) GetObject(key resources.ClusterObjectKey) (resources.Object, error) {
	return this.clusters.GetObject(key)
}

func (this *httpserver) GetCachedObject(key resources.ClusterObjectKey) (resources.Object, error) {
	return this.clusters.GetCachedObject(key)
}

func (this *httpserver) Server() *server.HTTPServer {
	return this.server
}

func (this *httpserver) Register(pattern string, handler http.HandlerFunc) {
	this.server.Register(pattern, handler)
}

func (this *httpserver) RegisterHandler(pattern string, handler http.Handler) {
	this.server.RegisterHandler(pattern, handler)
}

func (this *httpserver) handleSetup() error {
	this.Infof("setup server %s", this.definition.Name())
	for n, t := range this.definition.Handlers() {
		h, err := t(this)
		if err != nil {
			return err
		}
		this.handlers[n] = h
		if s, ok := h.(handler.SetupInterface); ok {
			this.Infof("  setup handler %s", n)
			err := s.Setup()
			if err != nil {
				return fmt.Errorf("setup of server %s handler %s failed: %s", this.definition.Name(), n, err)
			}
		}
	}
	return nil
}

func (this *httpserver) Start() error {
	var err error
	this.certificate, err = this.config.CertConfig.CreateAccess(this.GetContext(), this, this.cluster, this.env.Namespace(), secret.TLSKeys())
	if err != nil {
		return err
	}

	if w, ok := this.certificate.(certs.Watchable); ok {
		this.Infof("server certificate is watchable -> register change notification")
		w.RegisterConsumer(certs.CertificateUpdaterFunc(func(info certmgmt.CertificateInfo) {
			this.certificateUpdated()
		}))
	}
	this.Infof("starting %s server %s on port %d", this.definition.Kind(), this.definition.Name(), this.config.ServerPort)
	this.server.Start(this.certificate, "", this.config.ServerPort)
	return nil
}

func (this *httpserver) handleStart() error {
	this.Infof("start server %s", this.definition.Name())
	for n, h := range this.handlers {
		if s, ok := h.(handler.StartInterface); ok {
			this.Infof("  start handler %s", n)
			err := s.Start()
			if err != nil {
				return fmt.Errorf("start of server %s handler %s failed: %s", this.definition.Name(), n, err)
			}
		}
	}
	return nil
}

func (this *httpserver) certificateUpdated() {
	this.Infof("certificate for server %s updated", this.GetName())
}
