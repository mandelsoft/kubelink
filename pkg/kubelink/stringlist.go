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

package kubelink

type StringList []string

type StringLists []StringList

func (this StringList) Index(val string) int {
	for i, item := range this {
		if item == val {
			return i
		}
	}
	return -1
}

func (this StringList) Equals(r StringList) bool {
	if len(this) != len(r) {
		return false
	}
	for i, e := range this {
		if r[i] != e {
			return false
		}
	}
	return true
}

////////////////////////////////////////////////////////////////////////////////

func (this StringLists) Index(l StringList) int {
	for i, e := range this {
		if e.Equals(l) {
			return i
		}
	}
	return -1
}
