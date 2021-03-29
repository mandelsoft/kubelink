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
