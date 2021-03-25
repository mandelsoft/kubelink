/*
 * Copyright 2020 Mandelsoft. All rights reserved.
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

package broker

import (
	"github.com/gardener/controller-manager-library/pkg/config"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/vishvananda/netlink"

	"github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/controllers"
	ctrlcfg "github.com/mandelsoft/kubelink/pkg/controllers/broker/config"
	"github.com/mandelsoft/kubelink/pkg/iptables"
	"github.com/mandelsoft/kubelink/pkg/kubelink"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

type dummy struct{}

func (this *dummy) IsManagedRoute(*netlink.Route, kubelink.Routes) bool {
	return false
}

func (this *dummy) RequiredRoutes() kubelink.Routes {
	return nil
}

func (this *dummy) RequiredFirewallChains() iptables.Requests {
	return nil
}

func (this *dummy) RequiredNATChains() iptables.Requests {
	return nil
}

func (this *dummy) ConfirmManagedRoutes(list tcp.CIDRList) {
}

func (this *dummy) BaseConfig(cfg config.OptionSource) *controllers.Config {
	return &cfg.(*ctrlcfg.Config).Config
}

func (this *dummy) Gateway(obj *v1alpha1.KubeLink) (*controllers.LocalGatewayInfo, error) {
	return nil, nil
}

func (this *dummy) GetLinkInfo(link *v1alpha1.KubeLink) *controllers.LinkInfo {
	return nil
}

func (this *dummy) HandleDelete(logger logger.LogContext, name kubelink.LinkName, obj resources.Object) (bool, error) {
	return false, nil
}

func (this *dummy) HandleReconcile(logger logger.LogContext, obj resources.Object, entry *kubelink.Link) (error, error) {
	return nil, nil
}
