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

type Rule Options

func (this *Rule) Add(o Option) *Rule {
	if this.Index(o) < 0 {
		*this = append(*this, o)
	}
	return this
}

func (this Rule) Index(o Option) int {
	return Options(this).Index(o)
}

func (this Rule) Equals(r Rule) bool {
	if len(this) != len(r) {
		return false
	}
	for _, o := range r {
		if this.Index(o) < 0 {
			return false
		}
	}
	return true
}

func (this *Rule) HasOption(name string) bool {
	for _, r := range *this {
		if r[0] == name {
			return true
		}
	}
	return false
}

func (this *Rule) RemoveOption(name string) *Rule {
	for i, r := range *this {
		if r[0] == name {
			*this = append((*this)[:i], (*this)[i+1:]...)
		}
	}
	return this
}

func (this *Rule) Remove(o Option) *Rule {
	if i := this.Index(o); i >= 0 {
		*this = append((*this)[:i], (*this)[i+1:]...)
	}
	return this
}

func (this Rule) AsList() []string {
	l := []string{}
	for _, o := range this {
		l = append(l, o...)
	}
	return l
}

////////////////////////////////////////////////////////////////////////////////

type Rules []Rule

func (this *Rules) Add(r Rule) *Rules {
	if i := this.Index(r); i < 0 {
		*this = append(*this, r)
	}
	return this
}

func (this Rules) Index(r Rule) int {
	for i, e := range this {
		if e.Equals(r) {
			return i
		}
	}
	return -1
}

func ParseRule(list ...string) Rule {
	return Rule(registry.ParseOptions(list...))
}
