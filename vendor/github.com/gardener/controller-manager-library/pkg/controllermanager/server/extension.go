/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package server

import (
	"context"
	"strings"
	"time"

	"github.com/gardener/controller-manager-library/pkg/certs"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/cluster"
	parentcfg "github.com/gardener/controller-manager-library/pkg/controllermanager/config"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/extension"
	areacfg "github.com/gardener/controller-manager-library/pkg/controllermanager/server/config"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/server/ready"
	"github.com/gardener/controller-manager-library/pkg/ctxutil"
	"github.com/gardener/controller-manager-library/pkg/utils"
)

const TYPE = areacfg.OPTION_SOURCE

func init() {
	extension.RegisterExtension(&ExtensionType{DefaultRegistry()})
}

type ExtensionType struct {
	Registry
}

var _ extension.ExtensionType = &ExtensionType{}

func NewExtensionType() *ExtensionType {
	return &ExtensionType{NewRegistry()}
}

func (this *ExtensionType) Name() string {
	return TYPE
}

func (this *ExtensionType) Definition() extension.Definition {
	return NewExtensionDefinition(this.GetDefinitions())
}

////////////////////////////////////////////////////////////////////////////////

type ExtensionDefinition struct {
	extension.ExtensionDefinitionBase
	definitions Definitions
}

func NewExtensionDefinition(defs Definitions) *ExtensionDefinition {
	return &ExtensionDefinition{
		ExtensionDefinitionBase: extension.NewExtensionDefinitionBase(TYPE, []string{"modules"}),
		definitions:             defs,
	}
}

func (this *ExtensionDefinition) Description() string {
	return "server extension"
}

func (this *ExtensionDefinition) Size() int {
	return this.definitions.Size()
}

func (this *ExtensionDefinition) Names() utils.StringSet {
	return this.definitions.Names()
}

func (this *ExtensionDefinition) Validate() error {
	return nil
}

func (this *ExtensionDefinition) ExtendConfig(cfg *parentcfg.Config) {
	ecfg := areacfg.NewConfig()
	this.definitions.ExtendConfig(ecfg)
	cfg.AddSource(areacfg.OPTION_SOURCE, ecfg)
}

func (this *ExtensionDefinition) CreateExtension(cm extension.ControllerManager) (extension.Extension, error) {
	return NewExtension(this.definitions, cm)
}

////////////////////////////////////////////////////////////////////////////////

type Extension struct {
	extension.Environment

	config         *areacfg.Config
	definitions    Definitions
	registrations  Registrations
	defaultCluster cluster.Interface
	certificate    certs.CertificateSource
	servers        map[string]*httpserver
	clusters       utils.StringSet

	ready bool
}

func NewExtension(defs Definitions, cm extension.ControllerManager) (*Extension, error) {
	ctx := ctxutil.WaitGroupContext(cm.GetContext(), "server extension")
	ext := extension.NewDefaultEnvironment(ctx, TYPE, cm)
	cfg := areacfg.GetConfig(cm.GetConfig())

	groups := defs.Groups()
	ext.Infof("configured groups: %s", groups.AllGroups())

	active, err := groups.Members(ext, strings.Split(cfg.Servers, ","))
	if err != nil || active.IsEmpty() {
		return nil, err
	}

	registrations, err := defs.Registrations(active.AsArray()...)
	if err != nil {
		return nil, err
	}

	err = extension.ValidateElementConfigs(TYPE, cfg, active)
	if err != nil {
		return nil, err
	}

	this := &Extension{
		Environment:   ext,
		config:        cfg,
		definitions:   defs,
		registrations: registrations,
		servers:       map[string]*httpserver{},
	}
	this.clusters, err = this.definitions.DetermineRequestedClusters(cfg, this.ClusterDefinitions(), this.registrations)
	if err != nil {
		return nil, err
	}
	return this, nil
}

func (this *Extension) Maintainer() extension.MaintainerInfo {
	return this.ControllerManager().GetMaintainer()
}

func (this *Extension) GetConfig() *areacfg.Config {
	return this.config
}

func (this *Extension) RequiredClusters() (utils.StringSet, error) {
	return this.clusters, nil
}

func (this *Extension) RequiredClusterIds(clusters cluster.Clusters) utils.StringSet {
	return nil
}

func (this *Extension) Setup(ctx context.Context) error {
	ready.Register(this)
	return nil
}

func (this *Extension) IsReady() bool {
	return this.ready
}

func (this *Extension) Start(ctx context.Context) error {

	for _, def := range this.registrations {
		lines := strings.Split(def.String(), "\n")
		this.Infof("creating %s", lines[0])
		for _, l := range lines[1:] {
			this.Info(l)
		}
		cmp, err := this.definitions.GetMappingsFor(def.Name())
		if err != nil {
			return err
		}
		srv, err := NewServer(this, def, cmp)
		if err != nil {
			return err
		}

		this.servers[def.Name()] = srv
	}

	for _, srv := range this.servers {
		err := srv.handleSetup()
		if err != nil {
			return err
		}
	}

	for _, srv := range this.servers {
		err := srv.Start()
		if err != nil {
			return err
		}
	}

	for _, srv := range this.servers {
		err := srv.handleStart()
		if err != nil {
			return err
		}
	}
	this.ready = true
	ctxutil.WaitGroupRun(ctx, func() {
		<-this.GetContext().Done()
		this.Info("waiting for servers to shutdown")
		ctxutil.WaitGroupWait(this.GetContext(), 120*time.Second)
		this.Info("all servers down now")
	})

	return nil
}
