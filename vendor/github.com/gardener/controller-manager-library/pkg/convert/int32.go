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

var int32Type = reflect.TypeOf((*int32)(nil)).Elem()

func Int32Type() reflect.Type {
	return int32Type
}

func AsInt32(s interface{}) (int32, error) {
	if s == nil {
		return 0, nil
	}
	switch v := s.(type) {
	case int:
		return int32(v), nil
	case *int:
		return int32(*v), nil

	case uint:
		return int32(v), nil
	case *uint:
		return int32(*v), nil

	case int64:
		return int32(v), nil
	case *int64:
		return int32(*v), nil

	case uint64:
		return int32(v), nil
	case *uint64:
		return int32(*v), nil

	case int32:
		return int32(v), nil
	case *int32:
		return int32(*v), nil

	case uint32:
		return int32(v), nil
	case *uint32:
		return int32(*v), nil

	case int16:
		return int32(v), nil
	case *int16:
		return int32(*v), nil

	case uint16:
		return int32(v), nil
	case *uint16:
		return int32(*v), nil

	case int8:
		return int32(v), nil
	case *int8:
		return int32(*v), nil

	case uint8:
		return int32(v), nil
	case *uint8:
		return int32(*v), nil

	default:
		i64, err := ConvertTo(s, int64Type)
		if err == nil {
			return int32(i64.(int64)), nil
		}
		return 0, err
	}
}

func Int32(s interface{}) int32 {
	if v, err := AsInt32(s); err == nil {
		return v
	}
	return 0
}

func BestEffortInt32(s interface{}) int32 {
	if v, err := AsInt32(s); err == nil {
		return v
	}

	if v, err := AsString(s); err == nil {
		if i, err := strconv.ParseInt(v, 10, 32); err == nil {
			return int32(i)
		}
	}
	return 0
}
