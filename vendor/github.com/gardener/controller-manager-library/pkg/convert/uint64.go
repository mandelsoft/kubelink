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

var uint64Type = reflect.TypeOf((*uint64)(nil)).Elem()

func UInt64Type() reflect.Type {
	return uint64Type
}

func AsUInt64(s interface{}) (uint64, error) {
	if s == nil {
		return 0, nil
	}
	switch v := s.(type) {
	case int:
		return uint64(v), nil
	case *int:
		return uint64(*v), nil

	case uint:
		return uint64(v), nil
	case *uint:
		return uint64(*v), nil

	case int64:
		return uint64(v), nil
	case *int64:
		return uint64(*v), nil

	case uint64:
		return uint64(v), nil
	case *uint64:
		return uint64(*v), nil

	case int32:
		return uint64(v), nil
	case *int32:
		return uint64(*v), nil

	case uint32:
		return uint64(v), nil
	case *uint32:
		return uint64(*v), nil

	default:
		i64, err := ConvertTo(s, uint64Type)
		if err == nil {
			return i64.(uint64), nil
		}
		return 0, err
	}
}

func UInt64(s interface{}) uint64 {
	if v, err := AsUInt64(s); err == nil {
		return v
	}
	return 0
}

func BestEffortUInt64(s interface{}) uint64 {
	if v, err := AsUInt64(s); err == nil {
		return v
	}

	if v, err := AsString(s); err == nil {
		if i, err := strconv.ParseUint(v, 10, 64); err == nil {
			return uint64(i)
		}
	}
	return 0
}
