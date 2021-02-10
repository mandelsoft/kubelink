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
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gardener/controller-manager-library/pkg/ctxutil"
	"github.com/gardener/controller-manager-library/pkg/logger"

	"github.com/mandelsoft/kubelink/pkg/tcp"
)

type Server struct {
	logger.LogContext

	name string
	mux  *Mux
}

func NewServer(name string, mux *Mux) *Server {
	return &Server{
		LogContext: mux.LogContext,
		name:       name,
		mux:        mux,
	}
}

// Start starts a  server.
func (this *Server) Start(certInfo *CertInfo, bindAddress string, port int) {
	listenAddress := fmt.Sprintf("%s:%d", bindAddress, port)
	if certInfo != nil {
		this.Infof("starting %s as tls server (serving on %s)", this.name, listenAddress)
	} else {
		this.Infof("starting %s as unsecured server (serving on %s)", this.name, listenAddress)
	}
	server := &tcp.Server{
		Addr:      listenAddress,
		Handler:   this.mux,
		TLSConfig: certInfo.ServerConfig(),
	}

	ctxutil.WaitGroupAdd(this.mux.ctx)
	go func() {
		<-this.mux.ctx.Done()
		this.Infof("shutting down server %q with timeout", this.name)
		ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
		server.Shutdown(ctx)
	}()

	go func() {
		var err error
		this.Infof("server %q started", this.name)
		if certInfo != nil {
			err = server.ListenAndServeTLS("", "")
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			logger.Errorf("cannot start server %q: %s", this.name, err)
		}
		this.Infof("server %q stopped", this.name)
		ctxutil.Cancel(this.mux.ctx)
		ctxutil.WaitGroupDone(this.mux.ctx)
	}()
}
