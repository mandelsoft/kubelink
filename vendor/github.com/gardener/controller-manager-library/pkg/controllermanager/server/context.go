/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package server

import (
	"context"

	"github.com/gardener/controller-manager-library/pkg/ctxutil"
)

var ctx_server = ctxutil.NewValueKey(TYPE, (*httpserver)(nil))

func GetServer(ctx context.Context) Interface {
	return ctx.Value(ctx_server).(Interface)
}
