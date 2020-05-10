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

type DNSHandler struct {
	reconciler *reconciler
}

func (this *DNSHandler) GetAccess() kubelink.LinkAccessInfo {
	return this.reconciler.access
}

func (this *DNSHandler) UpdateAccess(hello *ConnectionHello) {
	link := this.reconciler.Links().GetLinkForClusterAddress(hello.GetClusterAddress())
	if link == nil {
		this.reconciler.Controller().Infof("local link not found for cluster address %s", hello.GetClusterAddress())
		return
	}
	ext := hello.Extensions[EXT_DNS]
	if ext == nil {
		this.reconciler.Controller().Infof("dns propagation not supported")
		return
	}
	dns := ext.(*DNSExtension)
	if link.Token != dns.Token || link.CACert != dns.CACert {
		this.reconciler.mux.Infof("got access info for link %s: %s", link.Name, dns)
		this.reconciler.updateLink(this.reconciler.mux, link.Name, *(*kubelink.LinkAccessInfo)(dns))
	}
}
