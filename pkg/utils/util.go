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

package utils

import (
	"fmt"
	"strings"

	"github.com/gardener/controller-manager-library/pkg/logger"
)

func Empty(s string) bool {
	return strings.TrimSpace(s) == ""
}

func ShortenString(s string, n int) string {
	l := len(s)
	if l > n {
		l = n
	} else {
		l = l / 2
	}
	return s[:l]
}

type Notifier struct {
	logger.LogContext
	pending []string
	active  bool
}

func (this *Notifier) Add(print bool, msg string, args ...interface{}) {
	if print || this.active {
		if len(this.pending) > 0 {
			for _, p := range this.pending {
				this.Info(p)
			}
			this.pending = nil
		}
		this.Infof(msg, args...)
		this.active = true
	} else {
		this.pending = append(this.pending, fmt.Sprintf(msg, args...))
	}
}
