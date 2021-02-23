/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"crypto/tls"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/server/ready"
)

/*
  Creation Flow for Handlers

  a) Handler Creation Time: Handler Creation by calling HandlerType function
  b) Before server starts: Calling Setup on all handlers
  c) Start server
  d) Calling Start on all handlers

*/

type Interface interface {
}

type SetupInterface interface {
	Setup() error
}

type StartInterface interface {
	Start() error
}

type LegacyInterface interface {
	Interface
	SetupInterface
	StartInterface
}

// TLSTweakInterface can be implemented by a handler to influence
// the actual tls config in case of a server of kind HTTPS
type TLSTweakInterface interface {
	TweakTLSConfig(ctf *tls.Config)
}

// ReadyInterface can be implemented by a handler to participate
// in the pod ready handling
type ReadyInterface interface {
	ready.ReadyReporter
}
