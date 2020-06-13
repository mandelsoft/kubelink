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
	"github.com/mandelsoft/kubelink/pkg/kubelink"
)

type DefaultConnectionHandler struct {
	reconciler *reconciler
}

func (this *DefaultConnectionHandler) GetAccess() kubelink.LinkAccessInfo {
	return this.reconciler.access
}

func (this *DefaultConnectionHandler) GetDNSInfo() kubelink.LinkDNSInfo {
	return this.reconciler.dnsInfo
}

func (this *DefaultConnectionHandler) UpdateAccess(hello *ConnectionHello) {
	link := this.reconciler.Links().GetLinkForClusterAddress(hello.GetClusterAddress())
	if link == nil {
		this.reconciler.Controller().Infof("local link not found for cluster address %s", hello.GetClusterAddress())
		return
	}

	var infoDNS *kubelink.LinkDNSInfo
	var infoAPI *kubelink.LinkAccessInfo
	ext := hello.Extensions[EXT_DNS]
	if ext != nil {
		dns := ext.(*DNSExtension)
		this.reconciler.Controller().Infof("found dns advertisement %s", dns)
		if !link.LinkDNSInfo.Equal(*(*kubelink.LinkDNSInfo)(dns)) {
			this.reconciler.mux.Infof("update dns info for link %s: %s", link.Name, dns)
			infoDNS = (*kubelink.LinkDNSInfo)(dns)
		}
	} else {
		this.reconciler.Controller().Infof("dns propagation not supported")
	}

	ext = hello.Extensions[EXT_APIACCESS]
	if ext != nil {
		api := ext.(*APIExtension)
		this.reconciler.Controller().Infof("found api advertisement %s", api)
		if link.Token != api.Token || link.CACert != api.CACert {
			this.reconciler.mux.Infof("update api access info for link %s: %s", link.Name, api)
			infoAPI = (*kubelink.LinkAccessInfo)(api)
		}
	} else {
		this.reconciler.Controller().Infof("api access propagation not supported")
	}

	if infoAPI != nil || infoDNS != nil {
		this.reconciler.updateLink(this.reconciler.mux, link.Name, infoAPI, infoDNS)
	}
}
