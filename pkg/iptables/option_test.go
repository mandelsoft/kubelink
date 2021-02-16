/*
 * Copyright 2021 Mandelsoft. All rights reserved.
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

package iptables_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/mandelsoft/kubelink/pkg/iptables"
)

var _ = Describe("Types", func() {

	It("string args", func() {
		a := iptables.Opt("a", "b")
		b := iptables.Opt("a", "b")
		c := iptables.Opt("a", "c")
		Expect(a.Equals(a)).To(BeTrue())
		Expect(a.Equals(b)).To(BeTrue())
		Expect(a.Equals(c)).To(BeFalse())
	})
	It("opt args", func() {
		a := iptables.ComposeOpt(iptables.Opt("a"), iptables.Opt("b"))
		b := iptables.ComposeOpt(iptables.Opt("a"), iptables.Opt("b"))
		c := iptables.ComposeOpt(iptables.Opt("b"), iptables.Opt("a"))
		d := iptables.ComposeOpt(iptables.Opt("b"), iptables.Opt("c"))
		e := iptables.ComposeOpt(iptables.Opt("a"), iptables.Opt("b"), iptables.Opt("c"))
		Expect(a.Equals(a)).To(BeTrue())
		Expect(a.Equals(b)).To(BeTrue())
		Expect(a.Equals(c)).To(BeTrue())
		Expect(a.Equals(d)).To(BeFalse())
		Expect(a.Equals(e)).To(BeFalse())
	})
	It("mixed args", func() {
		a := iptables.ComposeOpt(iptables.StringArg("test"), iptables.Opt("a"), iptables.Opt("b"))
		b := iptables.ComposeOpt(iptables.StringArg("test"), iptables.Opt("a"), iptables.Opt("b"))
		c := iptables.ComposeOpt(iptables.StringArg("test"), iptables.Opt("b"), iptables.Opt("a"))
		d := iptables.ComposeOpt(iptables.StringArg("test"), iptables.Opt("b"), iptables.Opt("c"))
		e := iptables.ComposeOpt(iptables.StringArg("test"), iptables.Opt("a"), iptables.Opt("b"), iptables.Opt("c"))
		f := iptables.ComposeOpt(iptables.StringArg("bla"), iptables.Opt("b"), iptables.Opt("c"))
		g := iptables.ComposeOpt(iptables.StringArg("test"), iptables.StringArg("bla"), iptables.Opt("b"), iptables.Opt("c"))
		Expect(a.Equals(a)).To(BeTrue())
		Expect(a.Equals(b)).To(BeTrue())
		Expect(a.Equals(c)).To(BeTrue())
		Expect(a.Equals(d)).To(BeFalse())
		Expect(a.Equals(e)).To(BeFalse())
		Expect(a.Equals(f)).To(BeFalse())
		Expect(a.Equals(g)).To(BeFalse())
	})

	It("nested args", func() {
		a := iptables.ComposeOpt(iptables.StringArg("test"), iptables.ComposeOpt(iptables.Opt("a"), iptables.Opt("b")), iptables.Opt("c"))
		b := iptables.ComposeOpt(iptables.StringArg("test"), iptables.ComposeOpt(iptables.Opt("a"), iptables.Opt("b")), iptables.Opt("c"))
		c := iptables.ComposeOpt(iptables.StringArg("test"), iptables.ComposeOpt(iptables.Opt("b"), iptables.Opt("a")), iptables.Opt("c"))
		d := iptables.ComposeOpt(iptables.StringArg("test"), iptables.Opt("c"), iptables.ComposeOpt(iptables.Opt("b"), iptables.Opt("a")))

		Expect(a.Equals(a)).To(BeTrue())
		Expect(a.Equals(b)).To(BeTrue())
		Expect(a.Equals(c)).To(BeTrue())
		Expect(a.Equals(d)).To(BeTrue())
	})
})
