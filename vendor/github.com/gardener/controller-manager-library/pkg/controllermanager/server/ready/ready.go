/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

package ready

import (
	"io"
	"net/http"

	"github.com/gardener/controller-manager-library/pkg/server"
)

func init() {
	server.Register("/ready", Ready)
}

// Ready is a HTTP handler for the /ready endpoint which responses with 200 OK status code
// if server is ready and with 500 Internal Server error status code otherwise.
func Ready(w http.ResponseWriter, r *http.Request) {
	ok, info := ReadyInfo()
	if ok {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}
	io.WriteString(w, info+"\n")
}
