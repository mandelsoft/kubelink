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

const T_STRING = infodata.TypeVersion("String")

func init() {
	infodata.Register(T_STRING, infodata.UnmarshalFunc((*String)(nil)))
}

type String string

func (this String) TypeVersion() infodata.TypeVersion {
	return T_STRING
}

func (this String) Marshal() ([]byte, error) {
	return json.Marshal(&this)
}
