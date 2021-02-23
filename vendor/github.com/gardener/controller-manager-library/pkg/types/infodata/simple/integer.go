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

const T_INTEGER = infodata.TypeVersion("Integer")

func init() {
	infodata.Register(T_INTEGER, infodata.UnmarshalFunc((*Integer)(nil)))
}

type Integer int64

func (this Integer) TypeVersion() infodata.TypeVersion {
	return T_INTEGER
}

func (this Integer) Marshal() ([]byte, error) {
	return json.Marshal(&this)
}
