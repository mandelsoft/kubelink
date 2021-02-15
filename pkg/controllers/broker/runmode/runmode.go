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

package runmode

import (
	"net"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/vishvananda/netlink"

	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/controllers"
	"github.com/mandelsoft/kubelink/pkg/controllers/broker/config"
	"github.com/mandelsoft/kubelink/pkg/iptables"
	"github.com/mandelsoft/kubelink/pkg/kubelink"
	"github.com/mandelsoft/kubelink/pkg/tasks"
)

type RunModeEnv interface {
	Controller() controller.Interface
	Config() *config.Config
	LinkTool() *controllers.LinkTool
	Secrets() *controllers.SecretCache
	Tasks() tasks.Tasks
	Links() *kubelink.Links

	GetAccess() kubelink.LinkAccessInfo
	GetDNSInfo() kubelink.LinkDNSInfo

	TriggerUpdate()
	UpdateLink(logger logger.LogContext, name string, access *kubelink.LinkAccessInfo, dns *kubelink.LinkDNSInfo)
}

type RunMode interface {
	Name() string
	Env() RunModeEnv

	Start() error
	Setup() error
	HandleDNSPropagation(klink *api.KubeLink)
	GetInterface() netlink.Link
	GetErrorForMeshNode(ip net.IP) error
	RequiredIPTablesChains() iptables.Requests
	ReconcileInterface(logger logger.LogContext) error
}

type RunModeBase struct {
	RunModeEnv
	name string
}

func NewRunModeBase(name string, env RunModeEnv) RunModeBase {
	return RunModeBase{
		RunModeEnv: env,
		name:       name,
	}
}

func (this *RunModeBase) Infof(msgfmt string, args ...interface{}) {
	this.Controller().Infof(msgfmt, args...)
}

func (this *RunModeBase) Errorf(msgfmt string, args ...interface{}) {
	this.Controller().Errorf(msgfmt, args...)
}

func (this *RunModeBase) Debugf(msgfmt string, args ...interface{}) {
	this.Controller().Debugf(msgfmt, args...)
}

////////////////////////////////////////////////////////////////////////////////

func (this *RunModeBase) Name() string {
	return this.name
}

func (this *RunModeBase) Env() RunModeEnv {
	return this.RunModeEnv
}

func (this *RunModeBase) Setup() error {
	return nil
}

func (this *RunModeBase) Start() error {
	return nil
}

func (this *RunModeBase) HandleDNSPropagation(klink *api.KubeLink) {
}

func (this *RunModeBase) GetInterface() netlink.Link {
	return nil
}

func (this *RunModeBase) GetErrorForMeshNode(ip net.IP) error {
	return nil
}

func (this *RunModeBase) RequiredIPTablesChains() iptables.Requests {
	return nil
}

func (this *RunModeBase) ReconcileInterface(logger logger.LogContext) error {
	return nil
}
