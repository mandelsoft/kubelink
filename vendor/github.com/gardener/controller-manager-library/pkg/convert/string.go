/*
 * Copyright 2020 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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
 *
 */

package convert

import (
	"encoding/json"
	"reflect"
)

var stringType = reflect.TypeOf((*string)(nil)).Elem()

func StringType() reflect.Type {
	return stringType
}

func AsString(s interface{}) (string, error) {
	if s == nil {
		return "", nil
	}
	switch v := s.(type) {
	case string:
		return v, nil
	case *string:
		return *v, nil
	default:
		i, err := ConvertTo(s, stringType)
		if err == nil {
			return i.(string), nil
		}
		return "", err
	}
}

func String(s interface{}) string {
	if v, err := AsString(s); err == nil {
		return v
	}
	return ""
}

func BestEffortString(s interface{}) string {
	if v, err := AsString(s); err == nil {
		return v
	}
	if m, _ := json.Marshal(s); m != nil {
		return string(m)
	}
	return ""
}
