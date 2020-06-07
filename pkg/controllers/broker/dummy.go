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
	"net"

	"github.com/vishvananda/netlink"

	"github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/controllers"
	"github.com/mandelsoft/kubelink/pkg/iptables"
	"github.com/mandelsoft/kubelink/pkg/kubelink"
)

type dummy struct{}

func (this *dummy) IsManagedRoute(*netlink.Route, kubelink.Routes) bool {
	return false
}

func (this *dummy) RequiredRoutes() kubelink.Routes {
	return nil
}

func (this *dummy) RequiredSNATRules() iptables.Requests {
	return nil
}

func (this *dummy) Config(cfg interface{}) *controllers.Config {
	return &cfg.(*Config).Config
}

func (this *dummy) Gateway(obj *v1alpha1.KubeLink) (net.IP, error) {
	return nil, nil
}

func (this *dummy) UpdateGateway(link *v1alpha1.KubeLink) *string {
	return nil
}
