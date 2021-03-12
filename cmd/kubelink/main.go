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

package main

import (
	"github.com/gardener/controller-manager-library/pkg/controllermanager"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/cluster"

	_ "github.com/gardener/controller-manager-library/pkg/resources/defaultscheme/v1.16"

	_ "github.com/mandelsoft/kubelink/pkg/controllers/broker"
	_ "github.com/mandelsoft/kubelink/pkg/controllers/router"
)

func init() {
	// enable api server override
	cluster.RegisterExtension(&cluster.APIServerOverride{})
}

func main() {
	controllermanager.Start("kubelink", "Launch KubeLink Controller Manager", "Kubelink manages network links among kubernetes clusters")
}
