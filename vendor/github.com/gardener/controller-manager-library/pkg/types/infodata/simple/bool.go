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

const T_BOOL = infodata.TypeVersion("Boolean")

func init() {
	infodata.Register(T_BOOL, infodata.UnmarshalFunc((*Bool)(nil)))
}

type Bool string

func (this Bool) TypeVersion() infodata.TypeVersion {
	return T_BOOL
}

func (this Bool) Marshal() ([]byte, error) {
	return json.Marshal(&this)
}
