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

var float64Type = reflect.TypeOf((*float64)(nil)).Elem()

func Float64Type() reflect.Type {
	return float64Type
}

func AsFloat64(s interface{}) (float64, error) {
	if s == nil {
		return 0, nil
	}
	switch v := s.(type) {
	case float32:
		return float64(v), nil
	case *float32:
		return float64(*v), nil

	case float64:
		return float64(v), nil
	case *float64:
		return float64(*v), nil

	default:
		f64, err := ConvertTo(s, float64Type)
		if err == nil {
			return float64(f64.(float64)), nil
		}
		return 0, err
	}
}

func Float64(s interface{}) float64 {
	if v, err := AsFloat64(s); err == nil {
		return v
	}
	return 0
}

func BestEffortFlat64(s interface{}) float64 {
	if v, err := AsFloat64(s); err == nil {
		return v
	}

	if v, err := AsString(s); err == nil {
		if i, err := strconv.ParseFloat(v, 64); err == nil {
			return float64(i)
		}
	}
	return 0
}
