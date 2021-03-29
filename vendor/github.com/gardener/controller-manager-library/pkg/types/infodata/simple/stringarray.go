/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 *
 */

package simple

import (
	"encoding/json"

	"github.com/gardener/controller-manager-library/pkg/types/infodata"
)

const T_STRINGARRAY = infodata.TypeVersion("StringArray")

func init() {
	infodata.Register(T_STRINGARRAY, infodata.UnmarshalFunc((StringArray)(nil)))
}

type StringArray []string

func (this StringArray) TypeVersion() infodata.TypeVersion {
	return T_STRINGARRAY
}

func (this StringArray) Marshal() ([]byte, error) {
	return json.Marshal(&this)
}
