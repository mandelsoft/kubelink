/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package server

import (
	"net/http"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/cluster"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/extension"
	areacfg "github.com/gardener/controller-manager-library/pkg/controllermanager/server/config"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/server/handler"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/gardener/controller-manager-library/pkg/server"
	"github.com/gardener/controller-manager-library/pkg/utils"
)

////////////////////////////////////////////////////////////////////////////////
// Definition
////////////////////////////////////////////////////////////////////////////////

const CLUSTER_MAIN = "<MAIN>"

type ServerKind string

const HTTP = ServerKind("http")
const HTTPS = ServerKind("https")

type HandlerType func(Interface) (handler.Interface, error)

type Environment interface {
	extension.Environment
	GetConfig() *areacfg.Config
}

type Interface interface {
	extension.ElementBase
	extension.SharedAttributes

	GetEnvironment() Environment

	GetMainCluster() cluster.Interface
	GetClusterById(id string) cluster.Interface
	GetCluster(name string) cluster.Interface
	GetClusterAliases(eff string) utils.StringSet
	GetDefinition() Definition

	GetKind() ServerKind

	Server() *server.HTTPServer

	Register(pattern string, handler http.HandlerFunc)
	RegisterHandler(pattern string, handler http.Handler)

	GetObject(key resources.ClusterObjectKey) (resources.Object, error)
	GetCachedObject(key resources.ClusterObjectKey) (resources.Object, error)
}

type OptionDefinition extension.OptionDefinition

type Definition interface {
	Name() string
	Kind() ServerKind
	Cluster() string
	RequiredClusters() []string
	ActivateExplicitly() bool
	AllowSecretMaintenance() bool

	ConfigOptions() extension.OptionDefinitions
	ConfigOptionSources() extension.OptionSourceDefinitions

	ServerPort() int

	Handlers() map[string]HandlerType

	Definition() Definition

	String() string
}
