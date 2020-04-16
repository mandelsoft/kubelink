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

package pkg

import (
	"fmt"
	"strconv"

	"github.com/mdlayher/ethernet"
)

func ParseEther(data []byte) (*ethernet.Frame, error) {
	var frame ethernet.Frame
	return &frame, frame.UnmarshalBinary(data)
}

func PrintEther(data []byte) {
	frame, err := ParseEther(data)
	if err != nil {
		fmt.Printf("err: %s\n", err)
	} else {
		t := strconv.FormatUint(uint64(frame.EtherType), 16)
		switch frame.EtherType {
		case ethernet.EtherTypeARP:
			t = "ARP"
		case ethernet.EtherTypeIPv4:
			t = "IPV4"
		case ethernet.EtherTypeIPv6:
			t = "IPV6"
		}
		fmt.Printf("packet: (%d) %s  %s->%s\n", len(data), t, frame.Source, frame.Destination)
	}
}
