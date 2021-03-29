/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
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
