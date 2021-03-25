/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 *
 */

package iptables_test

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/mandelsoft/kubelink/pkg/iptables"
)

func init() {
	RegisterTypeByArg("--all", 0, All)
}

const OPT = 1
const ARG = 2
const ADD = 3
const EXT = 4

func checkOption(mode int, args ...interface{}) {
	opt := ComposeOpt(args...)
	r := ParseRule(append(opt.AsArgs(), "rest")...)
	expected := Rule{opt}
	switch mode {
	case ADD:
		expected.Add(Opt("rest"))
	case ARG:
		expected[0].Add(StringArg("rest"))
	case OPT:
		expected[0].Add(Opt("rest"))
	case EXT:
		o := expected[0][len(expected[0])-1].(Option)
		o.Add(StringArg("rest"))
		expected[0][len(expected[0])-1] = o
	}

	Expect(r).To(Equal(expected))
}

func checkDirect(args ...Option) {
	expected := Rule(args)
	r := ParseRule(expected.AsList()...)
	fmt.Printf("rule: %#v\n", r)
	Expect(r).To(Equal(expected))
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
		args = append(args, o.AsArgs()...)
	}
	r := ParseRule(args...)
	Expect(r).To(Equal(Rule(opts)))
}

func checkMulti(add bool, opts ...Option) {
	var args []string
	for _, o := range opts {
		args = append(args, o.AsArgs()...)
	}
	r := ParseRule(append(args, "rest")...)
	expected := opts
	if add {
		if y, ok := expected[len(expected)-1][len(expected[len(expected)-1])-1].(Option); ok {
			y.Add(StringArg("rest"))
			expected[len(expected)-1][len(expected[len(expected)-1])-1] = y
		}
	} else {
		expected[len(expected)-1] = append(expected[len(expected)-1], Opt("rest"))
	}
	//Expect(append(inter(Options(r)), Opt("gomega"))).To(ConsistOf(append(inter(expected), Opt("gomega"))...))
	Expect(r).To(ConsistOf([]interface{}{expected}...)) // gomega elimates one array level if size is one
	ContainElements()
}

var _ = Describe("Types", func() {

	Context("Arg Opt", func() {
		It("should handle -d", func() {
			checkOption(ADD, "-d", "test")
		})
		It("should handle plain -d", func() {
			checkOpts(Opt("-d", "test"))
		})
		It("should handle incomplete -d at end", func() {
			checkOption(ARG, "-d")
		})
	})

	Context("Not", func() {
		It("should handle -m", func() {
			checkOption(ADD, "-m", "mark", Opt("!", "--mark", "0x2000:0x200"))
		})
	})

	Context("Nested Options", func() {
		It("should handle -m", func() {
			checkOption(ADD, "-m", "comment", Opt("--comment", "test"))
		})
		It("should handle wrong -m at end", func() {
			checkOption(EXT, "-m", "comment", Opt("--comment"))
		})
		It("should handle plain simple -j", func() {
			checkOpts(Opt("-j", "RETURN"))
		})
	})

	Context("Mixed", func() {
		It("should handle simple -j", func() {
			checkOption(OPT, "-j", "RETURN")
		})
		It("should handle complex -j", func() {
			checkMulti(false, ComposeOpt("-j", "MARK", Opt("--set-xmark", "test")))
		})
	})

	Context("Multi", func() {
		It("should handle simple", func() {
			checkMulti(false, Opt("-d", "test"), Opt("-j", "RETURN"))
		})
		It("should handle complex -j", func() {
			checkMulti(false, ComposeOpt("-m", "comment", Opt("--comment", "test")), ComposeOpt("-j", "MARK", Opt("--set-xmark", "test")))
		})

	})

	Context("Special", func() {
		It("should handle all", func() {
			checkMulti(true, ComposeOpt("--all", Opt("-x", "addr")))
		})
	})

	Context("rules", func() {
		It("comment", func() {
			checkDirect(R_CommentOpt("test"))
			checkDirect(R_DestOpt("1.1.1.1"), R_CommentOpt("test"))
		})
		It("snat", func() {
			checkDirect(R_DestOpt("1.1.1.1"), R_SNATOpt("2.2.2.2"))
		})
		It("setmark", func() {
			checkDirect(R_DestOpt("1.1.1.1"), R_SetXMarkOpt("0x0/0x0"))
		})
		It("checkmark", func() {
			checkDirect(R_DestOpt("1.1.1.1"), R_CheckMarkOpt("0x0/0x0"))
		})

		It("probability", func() {
			checkDirect(R_DestOpt("1.1.1.1"), R_ProbabilityOpt(0.5), R_DNATOpt("2.2.2.2"))
		})
	})

	Context("unknown", func() {
		It("mixed", func() {
			checkDirect(
				Opt("-A", "chain"),
				Opt("-m", "other", "-arg", "argument"),
				R_CommentOpt("test"),
				Opt("-other", "something", "else"),
				R_DropOpt(),
			)
		})
	})
})
