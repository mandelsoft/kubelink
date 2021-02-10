/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

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
