/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

package convert

import (
	"encoding/json"
	"reflect"
)

var stringType = reflect.TypeOf((*string)(nil)).Elem()

func StringType() reflect.Type {
	return stringType
}

func AsString(s interface{}) (string, error) {
	if s == nil {
		return "", nil
	}
	switch v := s.(type) {
	case string:
		return v, nil
	case *string:
		return *v, nil
	default:
		i, err := ConvertTo(s, stringType)
		if err == nil {
			return i.(string), nil
		}
		return "", err
	}
}

func String(s interface{}) string {
	if v, err := AsString(s); err == nil {
		return v
	}
	return ""
}

func BestEffortString(s interface{}) string {
	if v, err := AsString(s); err == nil {
		return v
	}
	if m, _ := json.Marshal(s); m != nil {
		return string(m)
	}
	return ""
}
