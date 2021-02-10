/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

package server

import (
	"net/http"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/server/handler"
)

func HandlerFunc(pattern string, h http.Handler) HandlerType {
	return func(s Interface) (handler.Interface, error) {
		return &_handler{
			server:  s,
			pattern: pattern,
			handler: h,
		}, nil
	}
}

type _handler struct {
	server  Interface
	pattern string
	handler http.Handler
}

func (this *_handler) Setup() error {
	this.server.Server().RegisterHandler(this.pattern, this.handler)
	if s, ok := this.handler.(handler.SetupInterface); ok {
		return s.Setup()
	}
	return nil
}

func (this *_handler) Start() error {
	if s, ok := this.handler.(handler.StartInterface); ok {
		return s.Start()
	}
	return nil
}
