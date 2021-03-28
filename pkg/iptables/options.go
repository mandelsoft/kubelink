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
	"fmt"
	"reflect"
	"sync"
)

////////////////////////////////////////////////////////////////////////////////
// Known structured iptables options, modules and module options
// all other options between known options will be parsed as single multi arg
// options.

func init() {
	RegisterTypeByArg("-m", 1,
		MultiOptType("tcp", 0,
			OptType("--dport", 1)),
		MultiOptType("udp", 0,
			OptType("--dport", 1)),
		MultiOptType("comment", 0,
			OptType("--comment", 1)),
		MultiOptType("mark", 0,
			OptType("--mark", 1)),
		MultiOptType("statistic", 0,
			OptType("--mode", 1),
			OptType("--probability", 1)))
	RegisterTypeByArg("-N", 1)
	RegisterTypeByArg("-A", 1)
	RegisterTypeByArg("-d", 1)
	RegisterTypeByArg("-s", 1)
	RegisterTypeByArg("-o", 1)
	RegisterTypeByArg("-i", 1)
	RegisterTypeByArg("-p", 1)
	RegisterTypeByArg("-g", 1)
	RegisterTypeByArg("-j", 1,
		//	Trailing("RETURN", 0),
		//	Trailing("DROP", 0),
		Trailing("MARK", 0,
			OptType("--set-xmark", 1),
		),
		Trailing("DNAT", 0,
			OptType("--to-destination", 1),
			OptType("---to-source", 1),
		),
		Trailing("SNAT", 0,
			OptType("---to-source", 1),
		),
		AllArg,
	)
}

////////////////////////////////////////////////////////////////////////////////
// Predefined iptable option support

func R_OutOpt(name string) Option {
	return Opt("-o", name)
}
func R_SourceOpt(addr string) Option {
	return Opt("-s", addr)
}
func R_DestOpt(addr string) Option {
	return Opt("-d", addr)
}
func R_PortFilter(proto string, port int32) Options {
	return Options{Opt("-p", proto), ComposeOpt("-m", proto, Opt("--dport", fmt.Sprintf("%d", port)))}
}

func R_JumpChainOpt(name string) Option {
	return Opt("-j", name)
}
func R_AcceptOpt() Option {
	return R_JumpChainOpt("ACCEPT")
}
func R_ReturnOpt() Option {
	return R_JumpChainOpt("RETURN")
}
func R_DropOpt() Option {
	return R_JumpChainOpt("DROP")
}
func R_MarkOpt(opt Option) Option {
	return ComposeOpt("-j", "MARK", opt)
}
func R_SetXMarkOpt(mark string) Option {
	return R_MarkOpt(Opt("--set-xmark", mark))
}
func R_CheckMarkOpt(mark string) Option {
	return ComposeOpt("-m", "mark", Opt("--mark", mark))
}
func R_SNATOpt(ip string) Option {
	return ComposeOpt("-j", "SNAT", Opt("--to-source", ip))
}
func R_DNATOpt(ip string) Option {
	return ComposeOpt("-j", "DNAT", Opt("--to-destination", ip))
}
func R_CommentOpt(c string) Option {
	return ComposeOpt("-m", "comment", Opt("--comment", c))
}
func R_ProbabilityOpt(propability float64) Option {
	return ComposeOpt("-m", "statistic", Opt("--mode", "random"), Opt("--probability", fmt.Sprintf("%.12f", propability)))
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
	r, list := this.ExtractOptions(list...)
	if len(list) > 0 {
		r.Add(Opt(list...))
	}
	return r
}

func (this *ruleOptions) ConsumeOptions(list ...string) (Options, []string) {
	this.lock.RLock()
	defer this.lock.RUnlock()

	r := Options{}
	found := true
	for found {
		found = false
		for _, t := range this.types {
			o, l := t.Consume(list)
			if o != nil {
				found = true
				r.Add(o...)
			}
			list = l
		}
	}
	return r, list
}

func (this *ruleOptions) ExtractOptions(list ...string) (Options, []string) {
	this.lock.RLock()
	defer this.lock.RUnlock()

	r := Options{}
	for i := 0; i < len(list); i++ {
		for _, t := range this.types {
			o, l := t.Consume(list[i:])
			if o != nil {
				if i > 0 {
					r.Add(Opt(list[:i]...))
				}
				r.Add(o...)
				list = l
				i = -1
				break
			}
		}
	}
	return r, list
}

var registry = &ruleOptions{}

func RegisterType(t OptionType) {
	registry.RegisterType(t)
}

func RegisterTypeByArg(name string, n int, nested ...NestedType) {
	RegisterType(OptType(name, n, nested...))
}

////////////////////////////////////////////////////////////////////////////////

type OptionType interface {
	Consume(list []string) (Options, []string)
}

////////////////////////////////////////////////////////////////////////////////

type optionType struct {
	options nestedType
}

func OptType(name string, n int, nested ...NestedType) OptionType {
	return &optionType{nestedType{name, n, nested}}
}

func (this *optionType) Consume(list []string) (Options, []string) {
	if c, opts, rest := this.options.Consume(list); c >= 0 {
		o := Opt(list[:c]...)
		for _, n := range opts {
			o.Add(n)
		}
		return Options{o}, rest
	}
	return nil, list
}

////////////////////////////////////////////////////////////////////////////////

type NestedType interface {
	Consume(list []string) (int, Options, []string)
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

func (this *nestedType) Consume(list []string) (int, Options, []string) {
	orig := list
	not := 0
	if len(list) > 0 && list[0] == "!" {
		not = 1
		list = list[1:]
	}
	if len(list) < 1 || list[0] != this.name {
		return -1, nil, orig
	}
	if this.types != nil {
		for _, sub := range this.types {
			if c, opts, rest := sub.Consume(list[1:]); c >= 0 {
				return c + 1, opts, rest
			}
		}
		return -1, nil, orig
	}
	if len(list) <= this.args {
		return -1, nil, orig
	}
	return not + this.args + 1, nil, list[this.args+1:]
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

func (this *trailingType) Consume(list []string) (int, Options, []string) {
	if len(list) < this.args+1 || list[0] != this.name {
		return -1, nil, list
	}
	var trailing Options
	if this.types.types != nil {
		// handle unknown trailing options as single additional option
		trailing = this.types.ParseOptions(list[this.args+1:]...)
	} else {
		trailing = Options{Opt(list[this.args+1:]...)}
	}
	return this.args + 1, trailing, list[:0:0]
}

////////////////////////////////////////////////////////////////////////////////

type multiOptType struct {
	name  string
	args  int
	types ruleOptions
}

func MultiOptType(name string, n int, nested ...OptionType) NestedType {
	t := &multiOptType{
		name: name,
		args: n,
	}
	for _, n := range nested {
		t.types.RegisterType(n)
	}
	return t
}

func (this *multiOptType) Consume(list []string) (int, Options, []string) {
	if len(list) < this.args+1 || list[0] != this.name {
		return -1, nil, list
	}
	if this.types.types != nil {
		// consume leading options as many as possible
		opts, list := this.types.ConsumeOptions(list[this.args+1:]...)
		return this.args + 1, opts, list
	} else {
		return this.args + 1, Options{}, list[this.args+1:]
	}
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

func (this all) Consume(list []string) (int, Options, []string) {
	if len(list) < this.args {
		return -1, nil, list
	}
	if len(list) == this.args {
		return this.args, Options{}, list[:0:0]
	}
	return this.args, Options{Opt(list[this.args:]...)}, list[:0:0]
}

////////////////////////////////////////////////////////////////////////////////

type OptionArg interface {
	AsArgs() []string
	Index(s string) int
	Equals(a OptionArg) bool
}

type StringArg string

func (this StringArg) AsArgs() []string {
	return []string{string(this)}
}

func (this StringArg) Equals(o OptionArg) bool {
	if o == nil {
		return false
	}
	s, ok := o.(StringArg)
	return ok && string(this) == string(s)
}

func (this StringArg) Index(s string) int {
	if string(this) == s {
		return 0
	}
	return -1
}

var _ OptionArg = StringArg("")

////////////////////////////////////////////////////////////////////////////////

type Option []OptionArg

func (this *Option) Add(args ...OptionArg) *Option {
	*this = append(*this, args...)
	return this
}

func (this Option) AsArgs() []string {
	var args []string
	for _, a := range this {
		args = append(args, a.AsArgs()...)
	}
	return args
}

func (this Option) Index(val string) int {
	for i, a := range this {
		if a.Index(val) == 0 {
			return i
		}
	}
	return -1
}

func (this Option) Equals(s OptionArg) bool {
	o, ok := s.(Option)
	if !ok || len(this) != len(o) {
		return false
	}

	for i, e := range this {
		if !o[i].Equals(e) {
			if _, ok := e.(StringArg); ok {
				return false
			}
		next:
			for _, e := range this[i:] {
				for _, n := range o[i:] {
					if e.Equals(n) {
						continue next
					}
				}
				return false
			}
			break
		}
	}
	return true
}

func Opt(args ...string) Option {
	r := make([]OptionArg, len(args))
	for i, v := range args {
		r[i] = StringArg(v)
	}
	return Option(r)
}

func R_Not(opt Option) Option {
	return append([]OptionArg{StringArg("!")}, []OptionArg(opt)...)
}

func ComposeOpt(args ...interface{}) Option {
	r := make([]OptionArg, len(args))
	for i, v := range args {
		switch o := v.(type) {
		case string:
			r[i] = StringArg(o)
		case OptionArg:
			r[i] = o
		case []interface{}:
			r[i] = ComposeOpt(o...)
		case []string:
			r[i] = Opt(o...)
		case Options:
			r[i] = o.AsOption()
		default:
			panic(fmt.Sprintf("invalid option arg type %T", v))
		}
	}
	return Option(r)
}

////////////////////////////////////////////////////////////////////////////////

type Options []Option

func (this Options) Index(opt Option) int {
	for i, e := range this {
		if e.Equals(opt) {
			return i
		}
	}
	return -1
}

func (this Options) AsOption() Option {
	n := Option{}
	for _, o := range this {
		n.Add(o)
	}
	return n
}

func (this *Options) Add(opts ...Option) *Options {
	for _, o := range opts {
		if this.Index(o) < 0 {
			*this = append(*this, o)
		}
	}
	return this
}

func (this *Options) Remove(opt Option) *Options {
	if i := this.Index(opt); i >= 0 {
		*this = append((*this)[:i], (*this)[i+1:]...)
	}
	return this
}

func (this Options) IndexOption(name string) int {
	for i, e := range this {
		if e.Index(name) == 0 {
			return i
		}
	}
	return -1
}

func (this Options) HasOption(name string) bool {
	for _, r := range this {
		if r.Index(name) == 0 {
			return true
		}
	}
	return false
}

func (this Options) GetOption(name string) Option {
	for _, r := range this {
		if r.Index(name) == 0 {
			return r
		}
	}
	return nil
}

func (this *Options) RemoveOption(name string) *Options {
	for _, r := range *this {
		if i := r.Index(name); i >= 0 {
			*this = append((*this)[:i], (*this)[i+1:]...)
			break
		}
	}
	return this
}

////////////////////////////////////////////////////////////////////////////////
