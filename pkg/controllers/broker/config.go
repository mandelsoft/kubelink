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
	"strings"

	"github.com/gardener/controller-manager-library/pkg/config"
	"github.com/gardener/controller-manager-library/pkg/utils"

	"github.com/mandelsoft/k8sbridge/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/k8sbridge/pkg/controllers"
)

type Config struct {
	controllers.Config

	address     string
	service     string
	responsible string

	ClusterAddress net.IP
	ClusterCIDR    *net.IPNet

	ServiceCIDR *net.IPNet

	Responsible utils.StringSet
	Port        int
}

func (this *Config) AddOptionsToSet(set config.OptionSet) {
	this.Config.AddOptionsToSet(set)
	set.AddStringOption(&this.service, "service-cidr", "", "", "CIDR of of local service network")
	set.AddStringOption(&this.address, "link-address", "", "", "CIDR of cluster in cluster network")
	set.AddStringOption(&this.responsible, "served-links", "", "all", "Comma separated list of links to serve")
	set.AddIntOption(&this.Port, "broker-port", "", 8088, "Port for broker")
}

func (this *Config) Prepare() error {
	err := this.Config.Prepare()

	this.ClusterAddress, this.ClusterCIDR, err = this.RequireCIDR(this.address, "link-address")
	if err != nil {
		return err
	}

	_, this.ServiceCIDR, err = this.OptionalCIDR(this.service, "service-cidr")
	if err != nil {
		return err
	}

	this.Responsible = utils.StringSet{}
	for _, l := range strings.Split(this.responsible, ",") {
		l = strings.TrimSpace(l)
		this.Responsible.Add(l)
	}
	if this.Responsible.Contains("all") {
		this.Responsible = utils.NewStringSet("all")
	}
	return nil
}

func (this *Config) MatchLink(obj *v1alpha1.KubeLink) (bool, net.IP) {
	ip, _, err := net.ParseCIDR(obj.Spec.ClusterAddress)
	if err != nil {
		return false, nil
	}
	if !this.Responsible.Contains("all") && !this.Responsible.Contains(obj.Name) {
		return false, nil
	}
	return this.ClusterCIDR.Contains(ip), ip
}
