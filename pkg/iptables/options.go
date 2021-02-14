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
	RegisterArgType("-m", 1,
		Nested("comment", 0,
			Nested("--comment", 1)),
		Nested("mark", 0,
			Nested("--mark", 1)))
	RegisterArgType("-N", 1)
	RegisterArgType("-A", 1)
	RegisterArgType("-d", 1)
	RegisterArgType("-s", 1)
	RegisterArgType("-o", 1)
	RegisterArgType("-i", 1)
	RegisterArgType("-j", 1,
		//	Trailing("RETURN", 0),
		//	Trailing("DROP", 0),
		Trailing("MARK", 0,
			ArgType("--set-xmark", 1),
		),
		Trailing("DNAT", 0,
			ArgType("--to-destination", 1),
			ArgType("---to-source", 1),
		),
		AllArg,
	)
}

type ruleOptions struct {
	lock  sync.RWMutex
	types []OptionType
}

func (this *ruleOptions) RegisterType(t OptionType) {
	this.lock.Lock()
	defer this.lock.Unlock()

	for _, e := range this.types {
		if reflect.DeepEqual(e, t) {
			return
		}
	}
	this.types = append(this.types, t)
}

func (this *ruleOptions) ParseOptions(list ...string) Options {
	this.lock.RLock()
	defer this.lock.RUnlock()

	r := Options{}
	for _, t := range this.types {
		o, l := t.Extract(list)
		if o != nil {
			r.Add(o...)
		}
		list = l
	}
	if len(list) > 0 {
		r.Add(Option(list))
	}
	return r
}

var registry = &ruleOptions{}

func RegisterType(t OptionType) {
	registry.RegisterType(t)
}

func RegisterArgType(name string, n int, nested ...NestedType) {
	RegisterType(ArgType(name, n, nested...))
}

////////////////////////////////////////////////////////////////////////////////

type OptionType interface {
	Extract(list []string) (Options, []string)
}

////////////////////////////////////////////////////////////////////////////////

type optionType struct {
	options nestedType
}

func ArgType(name string, n int, nested ...NestedType) OptionType {
	return &optionType{nestedType{name, n, nested}}
}

func (this *optionType) Extract(list []string) (Options, []string) {
	for i := range list {
		if c, total, opts := this.options.Consume(list[i:]); c >= 0 {
			o := Option(list[i : i+c])
			list = append(append(list[:0:0], list[:i]...), list[i+total:]...)
			return append(Options{o}, opts...), list
		}
	}
	return nil, list
}

////////////////////////////////////////////////////////////////////////////////

type NestedType interface {
	Consume(list []string) (int, int, Options)
}

func Nested(name string, n int, nested ...NestedType) NestedType {
	return &nestedType{
		name:  name,
		args:  n,
		types: nested,
	}
}

////////////////////////////////////////////////////////////////////////////////

type nestedType struct {
	name  string
	args  int
	types []NestedType
}

func (this *nestedType) Consume(list []string) (int, int, Options) {
	not := 0
	if len(list) > 0 && list[0] == "!" {
		not = 1
		list = list[1:]
	}
	if len(list) < 1 || list[0] != this.name {
		return -1, -1, nil
	}
	if this.types != nil {
		for _, sub := range this.types {
			if c, total, opts := sub.Consume(list[1:]); c >= 0 {
				return c + 1, total + 1, opts
			}
		}
		return -1, -1, nil
	}
	if len(list) <= this.args {
		return -1, -1, nil
	}
	return not + this.args + 1, not + this.args + 1, nil
}

////////////////////////////////////////////////////////////////////////////////

type trailingType struct {
	name  string
	args  int
	types ruleOptions
}

func Trailing(name string, n int, nested ...OptionType) NestedType {
	t := &trailingType{
		name: name,
		args: n,
	}
	for _, n := range nested {
		t.types.RegisterType(n)
	}
	return t
}

func (this *trailingType) Consume(list []string) (int, int, Options) {
	if len(list) < this.args+1 || list[0] != this.name {
		return -1, -1, nil
	}
	var trailing Options
	if this.types.types != nil {
		// handle unknown trailing options as single additional option
		trailing = this.types.ParseOptions(list[this.args+1:]...)
	} else {
		trailing = Options{Option(list[this.args+1:])}
	}
	return this.args + 1, len(list), trailing
}

////////////////////////////////////////////////////////////////////////////////

type any struct {
	args int
}

// Consume no more args (use as default for Nested)
var Any = any{0}

// Consume one more args (use as default for Nested)
var AnyArg = any{1}

func (this any) Consume(list []string) (int, int, Options) {
	if len(list) < this.args {
		return -1, -1, nil
	}
	return this.args, this.args, nil
}

type all struct {
	args int
}

// Consume no more arg and accept rest as single option (use as default for Trailing)
var All = all{0}

// Consume one more arg and accept rest as single option (use as default for Trailing)
var AllArg = all{1}

func (this all) Consume(list []string) (int, int, Options) {
	if len(list) < this.args {
		return -1, -1, nil
	}
	if len(list) == this.args {
		return this.args, len(list), Options{}
	}
	return this.args, len(list), Options{Option(list[this.args:])}
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

func (this *Options) Add(opts ...Option) *Options {
	for _, o := range opts {
		if this.Index(o) < 0 {
			*this = append(*this, o)
		}
	}
	return this
}

////////////////////////////////////////////////////////////////////////////////
