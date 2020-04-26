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
	"context"
	"fmt"
	"net"

	"github.com/mandelsoft/k8sbridge/pkg/tcp"
)

func main() {
	server := &tcp.Server{
		Addr:    ":8080",
		Handler: &handler{},
	}

	server.ListenAndServe()
}

type handler struct {
}

func (this *handler) ServeConnection(ctx context.Context, conn net.Conn) {
	fmt.Printf("Start connection\n")
	var buf [1024]byte

	for {
		n, err := conn.Read(buf[:])
		if n <= 0 || err != nil {
			fmt.Printf("finish connection: %s\n", err)
			conn.Close()
			return
		}
		fmt.Printf("got %d bytes\n", n)
	}
}
