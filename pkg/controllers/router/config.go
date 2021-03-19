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

package router

import (
	"fmt"
	"net"

	"github.com/gardener/controller-manager-library/pkg/config"

	"github.com/mandelsoft/kubelink/pkg/controllers"
)

type Config struct {
	controllers.Config

	podcidr string

	PodCIDR *net.IPNet
	Service string

	DataFile string
}

func (this *Config) AddOptionsToSet(set config.OptionSet) {
	this.Config.AddOptionsToSet(set)
	set.AddStringOption(&this.podcidr, "pod-cidr", "", "", "CIDR of pod network of cluster")
	set.AddStringOption(&this.Service, "service", "", "kubelink", "service to lookup endpoint for broker")
	set.AddStringOption(&this.DataFile, "datafile", "", "", "datafile for storing managed routes")
}

func (this *Config) Prepare() error {
	err := this.Config.Prepare()
	if err != nil {
		return err
	}

	_, this.PodCIDR, err = this.RequireCIDR(this.podcidr, "pod-cidr")
	if err != nil {
		return err
	}
	if this.Service == "" {
		return fmt.Errorf("broker service name required")
	}
	return nil
}
