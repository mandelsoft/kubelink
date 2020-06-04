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
	"reflect"
	"strconv"
)

var float32Type = reflect.TypeOf((*float32)(nil)).Elem()

func Float32Type() reflect.Type {
	return float32Type
}

func AsFloat32(s interface{}) (float32, error) {
	if s == nil {
		return 0, nil
	}
	switch v := s.(type) {
	case float32:
		return float32(v), nil
	case *float32:
		return float32(*v), nil

	case float64:
		return float32(v), nil
	case *float64:
		return float32(*v), nil

	default:
		f64, err := ConvertTo(s, float64Type)
		if err == nil {
			return float32(f64.(float64)), nil
		}
		return 0, err
	}
}

func Float32(s interface{}) float32 {
	if v, err := AsFloat32(s); err == nil {
		return v
	}
	return 0
}

func BestEffortFlat32(s interface{}) float32 {
	if v, err := AsFloat32(s); err == nil {
		return v
	}

	if v, err := AsString(s); err == nil {
		if i, err := strconv.ParseFloat(v, 64); err == nil {
			return float32(i)
		}
	}
	return 0
}
