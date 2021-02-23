/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 *
 */

package infodata

import (
	"fmt"
	"sync"

	"k8s.io/apimachinery/pkg/runtime"
)

// TypeVersion is the potentially versioned type name of an InfoData representation.
type TypeVersion string

// Unmarshaller is a factory to create a dedicated InfoData object from a byte stream
type Unmarshaller func(data []byte) (InfoData, error)

// InfoData is the common interface of all info data object types
type InfoData interface {
	TypeVersion() TypeVersion
	Marshal() ([]byte, error)
}

var lock sync.Mutex
var types = map[TypeVersion]Unmarshaller{}

// Register is used to register new InfoData type versions
func Register(typeversion TypeVersion, unmarshaller Unmarshaller) {
	lock.Lock()
	defer lock.Unlock()
	types[typeversion] = unmarshaller
}

// InfoDataEntry is the structure an InfoData object is stored
// in an InfoDataList
type InfoDataEntry struct {
	Name string               `json:"name"`
	Type TypeVersion          `json:"type"`
	Data runtime.RawExtension `json:"data"`
}

// InfoDataList is a store for labeled InfoData objects
type InfoDataList []InfoDataEntry

// Get returns the InfoData object with a dedicatd label stored
// in this list
func (this *InfoDataList) Get(name string) (InfoData, error) {
	for _, e := range *this {
		if e.Name == name {
			return Unmarshal(&e)
		}
	}
	return nil, nil
}

// Set is used to set an InfoData object for a dedicated label
func (this *InfoDataList) Set(name string, data InfoData) error {
	if data == nil {
		this.Delete(name)
		return nil
	}
	bytes, err := data.Marshal()
	if err != nil {
		return err
	}
	for _, e := range *this {
		if e.Name == name {
			e.Type = data.TypeVersion()
			e.Data.Raw = bytes
			e.Data.Object = nil
			return nil
		}
	}
	*this = append(*this, InfoDataEntry{name, data.TypeVersion(), runtime.RawExtension{bytes, nil}})
	return nil
}

// Delete deletes an InfoData object with the given label from the list
func (this *InfoDataList) Delete(name string) {
	for i, e := range *this {
		if e.Name == name {
			*this = append((*this)[:i], (*this)[i+1:]...)
			break
		}
	}
}

// Unmarshal is used to extract the Go representation of
// an InfoData entry
func Unmarshal(entry *InfoDataEntry) (InfoData, error) {
	lock.Lock()
	unmarshaller := types[entry.Type]
	lock.Unlock()
	if unmarshaller == nil {
		return nil, fmt.Errorf("unknown info data type %q", entry.Type)
	}
	data, err := unmarshaller(entry.Data.Raw)
	if err != nil {
		return nil, fmt.Errorf("cannot unmarshal data set %q of type %q: %s", entry.Name, entry.Type, err)
	}
	return data, err
}
