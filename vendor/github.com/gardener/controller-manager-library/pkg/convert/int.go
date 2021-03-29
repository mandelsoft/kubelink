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

var intType = reflect.TypeOf((*int)(nil)).Elem()

func IntType() reflect.Type {
	return intType
}

func AsInt(s interface{}) (int, error) {
	if s == nil {
		return 0, nil
	}
	switch v := s.(type) {
	case int:
		return v, nil
	case *int:
		return *v, nil

	case uint:
		return int(v), nil
	case *uint:
		return int(*v), nil

	case int64:
		return int(v), nil
	case *int64:
		return int(*v), nil

	case uint64:
		return int(v), nil
	case *uint64:
		return int(*v), nil

	case int32:
		return int(v), nil
	case *int32:
		return int(*v), nil

	case uint32:
		return int(v), nil
	case *uint32:
		return int(*v), nil

	case int16:
		return int(v), nil
	case *int16:
		return int(*v), nil

	case uint16:
		return int(v), nil
	case *uint16:
		return int(*v), nil

	case int8:
		return int(v), nil
	case *int8:
		return int(*v), nil

	case uint8:
		return int(v), nil
	case *uint8:
		return int(*v), nil

	default:
		i64, err := ConvertTo(s, int64Type)
		if err == nil {
			return int(i64.(int64)), nil
		}
		return 0, err
	}
}

func Int(s interface{}) int {
	if v, err := AsInt(s); err == nil {
		return v
	}
	return 0
}

func BestEffortInt(s interface{}) int {
	if v, err := AsInt(s); err == nil {
		return v
	}

	if v, err := AsString(s); err == nil {
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
			return int(i)
		}
	}
	return 0
}
