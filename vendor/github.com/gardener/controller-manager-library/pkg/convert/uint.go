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

var uintType = reflect.TypeOf((*uint)(nil)).Elem()

func UIntType() reflect.Type {
	return uintType
}

func AsUInt(s interface{}) (uint, error) {
	if s == nil {
		return 0, nil
	}
	switch v := s.(type) {
	case int:
		return uint(v), nil
	case *int:
		return uint(*v), nil

	case uint:
		return uint(v), nil
	case *uint:
		return uint(*v), nil

	case int64:
		return uint(v), nil
	case *int64:
		return uint(*v), nil

	case uint64:
		return uint(v), nil
	case *uint64:
		return uint(*v), nil

	case int32:
		return uint(v), nil
	case *int32:
		return uint(*v), nil

	case uint32:
		return uint(v), nil
	case *uint32:
		return uint(*v), nil

	case int16:
		return uint(v), nil
	case *int16:
		return uint(*v), nil

	case uint16:
		return uint(v), nil
	case *uint16:
		return uint(*v), nil

	case int8:
		return uint(v), nil
	case *int8:
		return uint(*v), nil

	case uint8:
		return uint(v), nil
	case *uint8:
		return uint(*v), nil

	default:
		i64, err := ConvertTo(s, uint64Type)
		if err == nil {
			return uint(i64.(uint64)), nil
		}
		return 0, err
	}
}

func UInt(s interface{}) uint {
	if v, err := AsUInt(s); err == nil {
		return v
	}
	return 0
}

func BestEffortUInt(s interface{}) uint {
	if v, err := AsUInt(s); err == nil {
		return v
	}

	if v, err := AsString(s); err == nil {
		if i, err := strconv.ParseUint(v, 10, 64); err == nil {
			return uint(i)
		}
	}
	return 0
}
