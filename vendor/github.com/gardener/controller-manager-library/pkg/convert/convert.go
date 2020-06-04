/*
 * Copyright 2020 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package convert

import (
	"fmt"
	"reflect"
)

// ConvertTo tries to convert an object to a dedicated type
// The type may be given by either a pointer to a prototype of the
// desired type or the final type object.
// If no pointer type is is desired the prototype might be of the
// desired type or a pointer to an object of this type
// Examples:
//     - reflect.Type("string")  ->  string
//     - "string"                ->  string
//     - (*string)(nil)          ->  string
//     - (**string)(nil)         -> *string
func ConvertTo(v interface{}, proto interface{}) (interface{}, error) {

	if v == nil {
		return nil, nil
	}
	if proto == nil {
		return nil, nil
	}
	t, ok := proto.(reflect.Type)
	if !ok {
		t = reflect.TypeOf(proto)
		if t.Kind() == reflect.Ptr {
			t = t.Elem()
		}
	}
	value := reflect.ValueOf(v)

	for {
		if value.Type() == t {
			return value.Interface(), nil
		}
		if value.Type().ConvertibleTo(t) {
			return value.Convert(t).Interface(), nil
		}
		if value.Kind() == reflect.Slice || value.Kind() == reflect.Array {
			if t.Kind() == reflect.Slice {
				ev := value.Type().Elem()
				et := t.Elem()
				if ev.ConvertibleTo(et) {
					slice := reflect.New(t).Elem()
					for i := 0; i < value.Len(); i++ {
						slice = reflect.Append(slice, value.Index(i).Convert(et))
					}
					return slice.Interface(), nil
				}
			}
		}

		if value.Kind() == reflect.Map && t.Kind() == reflect.Map {
			ev := value.Type().Elem()
			et := t.Elem()
			kv := value.Type().Key()
			kt := t.Key()
			if ev.ConvertibleTo(et) && kv.ConvertibleTo(kt) {
				m := reflect.MakeMap(t)
				i := value.MapRange()
				for i.Next() {
					m.SetMapIndex(i.Key().Convert(kt), i.Value().Convert(et))
				}
				return m.Interface(), nil
			}
		}

		if value.Kind() != reflect.Ptr || value.IsNil() {
			return nil, fmt.Errorf("%T is not convertibe to %s", v, t)
		}
		value = value.Elem()
	}
}
