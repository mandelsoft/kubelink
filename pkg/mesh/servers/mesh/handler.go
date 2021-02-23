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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/server"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/server/handler"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/server/ready"
	"github.com/gardener/controller-manager-library/pkg/utils"

	"github.com/mandelsoft/kubelink/pkg/mesh/database"
)

type meshhandler struct {
	database database.Meshes
	server   server.Interface
}

var _ ready.ReadyReporter = &meshhandler{}
var _ handler.TLSTweakInterface = &meshhandler{}

const PARAM_MESH = "mesh"
const PARAM_MEMBER = "member"
const PARAM_PEER = "peer"

func (this *meshhandler) IsReady() bool {
	return this.database.IsReady()
}

func (this *meshhandler) TweakTLSConfig(cfg *tls.Config) {
	cfg.ClientAuth = tls.RequireAnyClientCert
}

func (this *meshhandler) serveInfo(response http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()

	meshid := query[PARAM_MESH]
	if len(meshid) != 1 {
		this.error(response, http.StatusBadRequest, "one mesh parameter required")
		return
	}

	if request.TLS != nil {
		orgs := request.TLS.PeerCertificates[0].Subject.Organization
		if len(orgs) == 0 {
			this.error(response, http.StatusExpectationFailed, "wrong certificate information")
			return
		}
		found := false
		for _, o := range orgs {
			if o == meshid[0] {
				found = true
				break
			}
		}
		if !found {
			this.error(response, http.StatusUnauthorized, "certificate mismatch")
			return
		}
	}

	mesh := this.database.GetMeshById(meshid[0])
	if mesh == nil {
		this.error(response, http.StatusNotFound, "mesh %q not found", meshid[0])
		return
	}

	if request.TLS != nil {
		opts := mesh.GetVerifyOpts()
		if opts != nil {
			_, err := request.TLS.PeerCertificates[0].Verify(*opts)
			if err != nil {
				this.error(response, http.StatusUnauthorized, "%s", err)
				return
			}
		}
	}

	members := query[PARAM_MEMBER]
	if len(members) != 1 {
		this.error(response, http.StatusBadRequest, "member parameter missing")
		return
	}

	if request.TLS != nil {
		cn := request.TLS.PeerCertificates[0].Subject.CommonName
		if cn != members[0] {
			this.error(response, http.StatusUnauthorized, "certificate member mismatch")
			return
		}
	}

	m := members[0]
	info := &InfoResponse{}
	member := mesh.GetMemberById(m)
	if member == nil {
		this.error(response, http.StatusNotFound, "member %q not found", m)
		return
	}
	peers := query[PARAM_PEER]
	info.Member = CalculateView(mesh, member, utils.NewStringSet(peers...))

	data, err := json.Marshal(info)
	response.WriteHeader(http.StatusOK)
	if err == nil {
		response.Write(data)
	}
}

func (this *meshhandler) error(response http.ResponseWriter, status int, msg string, args ...interface{}) {
	r := &InfoResponse{
		Error: fmt.Sprintf(msg, args...),
	}
	response.WriteHeader(status)
	data, err := json.Marshal(r)
	if err == nil {
		response.Write(data)
	}
}
