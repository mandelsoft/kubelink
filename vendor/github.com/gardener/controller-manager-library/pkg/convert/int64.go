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

var int64Type = reflect.TypeOf((*int64)(nil)).Elem()

func Int64Type() reflect.Type {
	return int64Type
}

func AsInt64(s interface{}) (int64, error) {
	if s == nil {
		return 0, nil
	}
	switch v := s.(type) {
	case int:
		return int64(v), nil
	case *int:
		return int64(*v), nil

	case uint:
		return int64(v), nil
	case *uint:
		return int64(*v), nil

	case int64:
		return int64(v), nil
	case *int64:
		return int64(*v), nil

	case uint64:
		return int64(v), nil
	case *uint64:
		return int64(*v), nil

	case int32:
		return int64(v), nil
	case *int32:
		return int64(*v), nil

	case uint32:
		return int64(v), nil
	case *uint32:
		return int64(*v), nil

	case int16:
		return int64(v), nil
	case *int16:
		return int64(*v), nil

	case uint16:
		return int64(v), nil
	case *uint16:
		return int64(*v), nil

	case int8:
		return int64(v), nil
	case *int8:
		return int64(*v), nil

	case uint8:
		return int64(v), nil
	case *uint8:
		return int64(*v), nil

	default:
		i64, err := ConvertTo(s, int64Type)
		if err == nil {
			return i64.(int64), nil
		}
		return 0, err
	}
}

func Int64(s interface{}) int64 {
	if v, err := AsInt64(s); err == nil {
		return v
	}
	return 0
}

func BestEffortInt64(s interface{}) int64 {
	if v, err := AsInt64(s); err == nil {
		return v
	}

	if v, err := AsString(s); err == nil {
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
			return int64(i)
		}
	}
	return 0
}
