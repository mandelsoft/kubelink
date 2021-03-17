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

package broker

import (
	"fmt"

	"github.com/mandelsoft/kubelink/pkg/controllers/broker/config"
	"github.com/mandelsoft/kubelink/pkg/controllers/broker/runmode"
	"github.com/mandelsoft/kubelink/pkg/controllers/broker/runmode/bridge"
	"github.com/mandelsoft/kubelink/pkg/controllers/broker/runmode/wireguard"
)

func DefaultPort(mode string) int {
	switch mode {
	case config.RUN_MODE_BRIDGE:
		return bridge.DefaultPort
	case config.RUN_MODE_WIREGUARD:
		return wireguard.DefaultPort
	}
	return 0
}

func CreateRunMode(mode string, env runmode.RunModeEnv) (runmode.RunMode, error) {
	switch mode {
	case config.RUN_MODE_BRIDGE:
		return bridge.NewBridgeMode(env)
	case config.RUN_MODE_WIREGUARD:
		return wireguard.NewWireguardMode(env)
	case config.RUN_MODE_NONE:
		return runmode.NewNoneMode(env)
	}
	return nil, fmt.Errorf("invalid run mode %q", mode)
}
