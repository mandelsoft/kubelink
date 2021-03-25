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

package main

import (
	"fmt"
	"os"
	"strings"
)

func Error(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "*** Error: "+msg+"\n", args...)
	os.Exit(1)
}

func main() {
	var args []string
	for _, a := range os.Args[1:] {
		if strings.HasSuffix(a, "-") {
			switch a {
			default:
				Error("invalid option %q", a)
			}
		} else {
			args = append(args, a)
		}
	}

	if len(args) == 0 {
		Error("command missing")
	}
	switch args[0] {
	case "routelist":
		listRoutes(args[1:])
	case "routeadd":
		addRoute(args[1:])
	case "linklist":
		listLinks()
	case "rulelist":
		listRules()
	case "ruleadd":
		addRule(args[1:])
	default:
		Error("invalid command %q", args[0])
	}
}
