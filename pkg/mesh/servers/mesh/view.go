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

package mesh

import (
	"github.com/gardener/controller-manager-library/pkg/utils"

	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/mesh/database"
)

func CalculateView(mesh database.Mesh, m database.Member, peers utils.StringSet) *MemberInfo {
	info := &MemberInfo{PeerInfo: *getPeerInfo(mesh, m)}

	if len(peers)== 0 {
		peers=mesh.GetMembers()
	}

	// add routes (and peers) to served members
	for g := range m.GetServedMembers() {
		if served := mesh.GetMemberById(g); served !=nil {
		    peers.Add(g) // enforce peer using this member as gateway
			info.Routes = append(info.Routes, api.MeshMemberRoute{served.GetAddress().String()})
			for _, r := range served.GetRoutes() {
				info.Routes = append(info.Routes, api.MeshMemberRoute{r.CIDR().String()})
			}
		}
	}

	peerInfos:=map[string]*PeerInfo{}
	for p := range peers {
		if peer := mesh.GetMemberById(p); peer !=nil {
			enrichPeerView(mesh, peerInfos, peer, m)
		}
	}

	for _, i := range peerInfos {
		info.Peers = append(info.Peers, *i)
	}
	return info
}

func getPeerInfo(mesh database.Mesh, m database.Member) *PeerInfo {
	info := &PeerInfo{Identity: m.GetId()}

	var routes []api.MeshMemberRoute
	if m.GetPublicKey() != nil {
		info.PublicKey = m.GetPublicKey().String()
	}
	if m.GetAddress() != nil {
		info.Address = m.GetAddress().String()
	}
	for _, r := range m.GetRoutes() {
		routes = append(routes, api.MeshMemberRoute{r.CIDR().String()})
	}
	info.Routes = routes
	return info
}

func enrichPeerView(mesh database.Mesh, peers map[string]*PeerInfo, m database.Member, view database.Member) *PeerInfo {
	if m==view {
		return nil
	}
	if peers[m.GetId()]!=nil {
		return peers[m.GetId()]
	}

	info:=getPeerInfo(mesh, m)

	groups:=view.GetEndpoints()
	found:=""
	gw:=m
	for gw!=nil && found=="" {
		found=findEndpoint(groups, gw)
		if found=="" {
			next:=gw.GetGateway()
			if next==nil {
				gw=nil
			} else {
				gw=mesh.GetMemberByName(next)
			}
		}
	}

	if found!="" {
		if m==gw {
			info.Endpoint=found
		} else {
			info.Gateway=gw.GetId()
			ext:=enrichPeerView(mesh, peers, gw, view)
			if ext!=nil {
				// add routes for target to gateway peer
				ext.AddRoutes(info.Routes...)
				ext.AddRoutes((api.MeshMemberRoute{m.GetAddress().String()}))
			}
		}

	}
	peers[m.GetId()]=info
	return info
}

func findEndpoint(groups map[string]string, m database.Member) string {
	found:=""
	for g, ep := range m.GetEndpoints() {
		if found=="" || found==database.EP_PUBLIC {
			if _, ok := groups[g]; ok {
				found=ep
			}
		}
	}
	return found
}