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

var uint8Type = reflect.TypeOf((*uint8)(nil)).Elem()

func UInt8Type() reflect.Type {
	return uint8Type
}

func AsUInt8(s interface{}) (uint8, error) {
	if s == nil {
		return 0, nil
	}
	switch v := s.(type) {
	case int:
		return uint8(v), nil
	case *int:
		return uint8(*v), nil

	case uint:
		return uint8(v), nil
	case *uint:
		return uint8(*v), nil

	case int64:
		return uint8(v), nil
	case *int64:
		return uint8(*v), nil

	case uint64:
		return uint8(v), nil
	case *uint64:
		return uint8(*v), nil

	case int32:
		return uint8(v), nil
	case *int32:
		return uint8(*v), nil

	case uint32:
		return uint8(v), nil
	case *uint32:
		return uint8(*v), nil
	case int16:
		return uint8(v), nil
	case *int16:
		return uint8(*v), nil

	case uint16:
		return uint8(v), nil
	case *uint16:
		return uint8(*v), nil

	case int8:
		return uint8(v), nil
	case *int8:
		return uint8(*v), nil

	case uint8:
		return uint8(v), nil
	case *uint8:
		return uint8(*v), nil

	default:
		i64, err := ConvertTo(s, uint64Type)
		if err == nil {
			return uint8(i64.(uint64)), nil
		}
		return 0, err
	}
}

func UInt8(s interface{}) uint8 {
	if v, err := AsUInt8(s); err == nil {
		return v
	}
	return 0
}

func BestEffortUInt8(s interface{}) uint8 {
	if v, err := AsUInt8(s); err == nil {
		return v
	}

	if v, err := AsString(s); err == nil {
		if i, err := strconv.ParseUint(v, 10, 64); err == nil {
			return uint8(i)
		}
	}
	return 0
}
