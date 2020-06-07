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

package iptables

import (
	"reflect"
	"sync"
)

func init() {
	RegisterArgType("-N", 1)
	RegisterArgType("-A", 1)
	RegisterArgType("-d", 1)
	RegisterArgType("-o", 1)
	RegisterArgType("-i", 1)
	RegisterArgType("-j", 1)
	RegisterArgType("--to-source", 1)
}

var lock sync.RWMutex
var types []OptionType

func RegisterType(t OptionType) {
	lock.Lock()
	defer lock.Unlock()

	for _, e := range types {
		if reflect.DeepEqual(e, t) {
			return
		}
	}
	types = append(types, t)
}

////////////////////////////////////////////////////////////////////////////////

type OptionType interface {
	Extract(list []string) (Option, []string)
}

////////////////////////////////////////////////////////////////////////////////

type optionType struct {
	name string
	args int
}

func RegisterArgType(name string, n int) {
	RegisterType(&optionType{name, n})
}

func (this *optionType) Extract(list []string) (Option, []string) {
	if i := StringList(list).Index(this.name); i >= 0 {
		if len(list) > i+this.args {
			o := Option(list[i : i+this.args+1])
			list = append(append(list[:0:0], list[:i]...), list[i+this.args+1:]...)
			return o, list
		}
	}
	return nil, list
}

////////////////////////////////////////////////////////////////////////////////

type Option []string

func (this Option) Index(val string) int {
	return StringList(this).Index(val)
}

func (this Option) Equals(s Option) bool {
	if len(this) != len(s) {
		return false
	}
	for i, e := range this {
		if s[i] != e {
			return false
		}
	}
	return true
}

func Opt(args ...string) Option {
	return Option(args)
}

////////////////////////////////////////////////////////////////////////////////

type Options []Option

func (this Options) Index(o Option) int {
	for i, e := range this {
		if e.Equals(o) {
			return i
		}
	}
	return -1
}

////////////////////////////////////////////////////////////////////////////////
