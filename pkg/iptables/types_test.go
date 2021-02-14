/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 *
 */

package iptables_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/mandelsoft/kubelink/pkg/iptables"
)

func init() {
	RegisterArgType("--all", 0, All)
}

func check(match bool, args ...string) {
	opt := Opt(args...)
	r := ParseRule(append(opt, "rest")...)
	expected := Rule{opt, Opt("rest")}
	if match {
		Expect(r).To(Equal(expected))
	} else {
		Expect(r).To(Equal(Rule{Opt(append(opt, "rest")...)}))
		ContainElements()
	}
}

func inter(r Options) []interface{} {
	var i []interface{}
	for _, e := range r {
		i = append(i, e)
	}
	return i
}

func checkOpts(opts ...Option) {
	var args []string
	for _, o := range opts {
		args = append(args, o...)
	}
	r := ParseRule(args...)
	Expect(r).To(Equal(Rule(opts)))
}

func checkMulti(sep bool, opts ...Option) {
	var args []string
	for _, o := range opts {
		args = append(args, o...)
	}
	r := ParseRule(append(args, "rest")...)
	expected := opts
	if sep {
		expected = append(opts, Opt("rest"))
	} else {
		expected[len(expected)-1] = append(expected[len(expected)-1], "rest")
	}
	Expect(r).To(ConsistOf(inter(expected)...))
}

var _ = Describe("Types", func() {

	Context("Arg Opt", func() {
		It("should handle -d", func() {
			check(true, "-d", "test")
		})
		It("should handle plain -d", func() {
			checkOpts(Opt("-d", "test"))
		})
		It("should handle incomplete -d at end", func() {
			check(false, "-d")
		})
	})

	Context("Not", func() {
		It("should handle -m", func() {
			check(true, "-m", "mark", "!", "--mark", "0x2000:0x200")
		})
	})

	Context("Nested Options", func() {
		It("should handle -m", func() {
			check(true, "-m", "comment", "--comment", "test")
		})
		It("should handle wrong -m at end", func() {
			check(false, "-m", "comment", "--comment")
		})
		It("should handle plain simple -j", func() {
			checkOpts(Opt("-j", "RETURN"))
		})
	})

	Context("Mixed", func() {
		It("should handle simple -j", func() {
			check(true, "-j", "RETURN")
			checkOpts(Opt("-j", "RETURN"))
		})
		It("should handle complex -j", func() {
			checkMulti(true, Opt("-j", "MARK"), Opt("--set-xmark", "test"))
		})
	})

	Context("Multi", func() {
		It("should handle simple", func() {
			checkMulti(true, Opt("-d", "test"), Opt("-j", "RETURN"))
		})
		It("should handle complex -j", func() {
			checkMulti(true, Opt("-m", "comment", "--comment", "test"), Opt("-j", "MARK"), Opt("--set-xmark", "test"))
		})

	})

	Context("Special", func() {
		It("should handle all", func() {
			checkMulti(false, Opt("--all"), Opt("-x", "addr"))
		})
	})
})
