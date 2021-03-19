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

package tcp_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/mandelsoft/kubelink/pkg/tcp"
)

var _ = Describe("Config", func() {
	cidrNet, _ := tcp.ParseIPCIDR("10.0.0.0/23")
	cidrSubNet1, _ := tcp.ParseIPCIDR("10.0.0.0/24")
	cidrSubNet2, _ := tcp.ParseIPCIDR("10.0.1.0/24")

	cidrIP1, _ := tcp.ParseIPCIDR("10.0.0.5/32")
	cidrIP2, _ := tcp.ParseIPCIDR("10.0.0.6/32")
	cidrIP3, _ := tcp.ParseIPCIDR("10.0.1.6/32")
	cidrIP4, _ := tcp.ParseIPCIDR("10.0.1.7/32")

	_ = cidrNet
	_ = cidrSubNet1
	_ = cidrSubNet2
	_ = cidrIP1
	_ = cidrIP2
	_ = cidrIP3
	_ = cidrIP4

	Context("cidr list", func() {
		Context("add", func() {
			It("add non overlapping", func() {

				list := tcp.CIDRList{}
				list.Add(cidrSubNet1, cidrIP3, cidrIP4)

				Expect(list).To(Equal(tcp.CIDRList{cidrSubNet1, cidrIP3, cidrIP4}))
			})
			It("add duplicate", func() {

				list := tcp.CIDRList{}
				list.Add(cidrSubNet1, cidrIP3, cidrSubNet1, cidrIP4)

				Expect(list).To(Equal(tcp.CIDRList{cidrSubNet1, cidrIP3, cidrIP4}))
			})
			It("simple overlapping", func() {

				list := tcp.CIDRList{}
				list.Add(cidrSubNet1, cidrIP2, cidrIP4)

				Expect(list).To(Equal(tcp.CIDRList{cidrSubNet1, cidrIP2, cidrIP4}))
			})
			It("replace single overlapping", func() {

				list := tcp.CIDRList{}
				list.Add(cidrIP2, cidrSubNet1, cidrIP4)

				Expect(list).To(Equal(tcp.CIDRList{cidrIP2, cidrSubNet1, cidrIP4}))
			})
			It("replace double overlapping", func() {

				list := tcp.CIDRList{}
				list.Add(cidrIP1, cidrIP2, cidrSubNet1, cidrIP4)

				Expect(list).To(Equal(tcp.CIDRList{cidrIP1, cidrIP2, cidrSubNet1, cidrIP4}))
			})
			It("mixed single overlapping", func() {

				list := tcp.CIDRList{}
				list.Add(cidrIP2, cidrSubNet1, cidrIP1, cidrIP4)

				Expect(list).To(Equal(tcp.CIDRList{cidrIP2, cidrSubNet1, cidrIP1, cidrIP4}))
			})
		})
		Context("enrich", func() {
			It("add non overlapping", func() {

				list := tcp.CIDRList{}
				list.Enrich(cidrSubNet1, cidrIP3, cidrIP4)

				Expect(list).To(Equal(tcp.CIDRList{cidrSubNet1, cidrIP3, cidrIP4}))
			})
			It("add duplicate", func() {

				list := tcp.CIDRList{}
				list.Enrich(cidrSubNet1, cidrIP3, cidrSubNet1, cidrIP4)

				Expect(list).To(Equal(tcp.CIDRList{cidrSubNet1, cidrIP3, cidrIP4}))
			})
			It("simple overlapping", func() {

				list := tcp.CIDRList{}
				list.Enrich(cidrSubNet1, cidrIP2, cidrIP4)

				Expect(list).To(Equal(tcp.CIDRList{cidrSubNet1, cidrIP4}))
			})
			It("replace single overlapping", func() {

				list := tcp.CIDRList{}
				list.Enrich(cidrIP2, cidrSubNet1, cidrIP4)

				Expect(list).To(Equal(tcp.CIDRList{cidrSubNet1, cidrIP4}))
			})
			It("replace double overlapping", func() {

				list := tcp.CIDRList{}
				list.Enrich(cidrIP1, cidrIP2, cidrSubNet1, cidrIP4)

				Expect(list).To(Equal(tcp.CIDRList{cidrSubNet1, cidrIP4}))
			})
			It("mixed single overlapping", func() {

				list := tcp.CIDRList{}
				list.Enrich(cidrIP2, cidrSubNet1, cidrIP1, cidrIP4)

				Expect(list).To(Equal(tcp.CIDRList{cidrSubNet1, cidrIP4}))
			})
		})
	})
})
