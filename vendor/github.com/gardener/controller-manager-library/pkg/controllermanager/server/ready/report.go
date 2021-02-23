/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

package ready

import (
	"fmt"
	"sync"
)

type ReadyReporter interface {
	IsReady() bool
}

var lock sync.Mutex
var reporters []ReadyReporter

func Register(reporter ReadyReporter) {
	lock.Lock()
	defer lock.Unlock()

	reporters = append(reporters, reporter)
}

func ReadyInfo() (bool, string) {
	lock.Lock()
	defer lock.Unlock()

	if len(reporters) == 0 {
		return false, "no ready reporter configured"
	}
	ready_cnt := 0
	notready_cnt := 0
	for _, r := range reporters {
		if r.IsReady() {
			ready_cnt++
		} else {
			notready_cnt++
		}
	}
	return notready_cnt == 0, fmt.Sprintf("ready: %d, not ready %d", ready_cnt, notready_cnt)
}
