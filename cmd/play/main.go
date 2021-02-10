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

package main

import (
	"fmt"
	"os"
	"reflect"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const NAME = "wireguard"

func CheckErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

var lnf = reflect.TypeOf(&netlink.LinkNotFoundError{}).Elem()

func IsLinkNotFound(err error) bool {
	return err != nil && reflect.ValueOf(err).Type() == lnf
}

func main() {
	fmt.Printf("Hello Wireguard\n")
	link, err := netlink.LinkByName(NAME)
	if IsLinkNotFound(err) {
		fmt.Printf("creating link\n")
		attrs := netlink.NewLinkAttrs()
		attrs.Name = NAME
		link = &netlink.GenericLink{
			LinkAttrs: attrs,
			LinkType:  "wireguard",
		}
		err = netlink.LinkAdd(link)
	}
	CheckErr(err)
	fmt.Printf("Link: %s %+v\n", link.Type(), link.Attrs())

	c, err := wgctrl.New()
	CheckErr(err)

	port := 8777
	key, err := wgtypes.GeneratePrivateKey()
	CheckErr(err)
	config := wgtypes.Config{
		//pub := key.PublicKey()
		PrivateKey: &key,
		ListenPort: &port,
	}
	_ = config
	fmt.Printf("configure with key %s\n", key.PublicKey())
	err = c.ConfigureDevice(NAME, config)
	CheckErr(err)
	devs, err := c.Devices()
	CheckErr(err)
	fmt.Printf("%s\n", devs)
	/*
	 */
}
