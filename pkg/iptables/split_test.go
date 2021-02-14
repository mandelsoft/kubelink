/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 *
 */

package iptables

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Types", func() {

	It("words", func() {
		Expect(Fields("  alice   peter and bob ")).To(Equal([]string{"alice", "peter", "and", "bob"}))
	})

	It("quoted strings", func() {
		Expect(Fields(`  "alice"   "peter and" bob  `)).To(Equal([]string{"alice", "peter and", "bob"}))
	})
})
