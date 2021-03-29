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

var uint16Type = reflect.TypeOf((*uint16)(nil)).Elem()

func UInt16Type() reflect.Type {
	return uint16Type
}

func AsUInt16(s interface{}) (uint16, error) {
	if s == nil {
		return 0, nil
	}
	switch v := s.(type) {
	case int:
		return uint16(v), nil
	case *int:
		return uint16(*v), nil

	case uint:
		return uint16(v), nil
	case *uint:
		return uint16(*v), nil

	case int64:
		return uint16(v), nil
	case *int64:
		return uint16(*v), nil

	case uint64:
		return uint16(v), nil
	case *uint64:
		return uint16(*v), nil

	case int32:
		return uint16(v), nil
	case *int32:
		return uint16(*v), nil

	case uint32:
		return uint16(v), nil
	case *uint32:
		return uint16(*v), nil
	case int16:
		return uint16(v), nil
	case *int16:
		return uint16(*v), nil

	case uint16:
		return uint16(v), nil
	case *uint16:
		return uint16(*v), nil

	case int8:
		return uint16(v), nil
	case *int8:
		return uint16(*v), nil

	case uint8:
		return uint16(v), nil
	case *uint8:
		return uint16(*v), nil

	default:
		i64, err := ConvertTo(s, uint64Type)
		if err == nil {
			return uint16(i64.(uint64)), nil
		}
		return 0, err
	}
}

func UInt16(s interface{}) uint16 {
	if v, err := AsUInt16(s); err == nil {
		return v
	}
	return 0
}

func BestEffortUInt16(s interface{}) uint16 {
	if v, err := AsUInt16(s); err == nil {
		return v
	}

	if v, err := AsString(s); err == nil {
		if i, err := strconv.ParseUint(v, 10, 64); err == nil {
			return uint16(i)
		}
	}
	return 0
}
