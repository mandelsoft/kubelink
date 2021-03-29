/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

package convert

import (
	"github.com/gardener/controller-manager-library/pkg/utils"
)

// Interface maps nil struct pointer interfaces to nil.
// Interfaces not referring to an object will be converted to nil
func Interface(i interface{}) interface{} {
	if utils.IsNil(i) {
		return nil
	}
	return i
}
