/*
 * Copyright 2020 Mandelsoft. All rights reserved.
 *  This file is licensed under the Apache Software License, v. 2 except as noted
 *  otherwise in the LICENSE file
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
 */

package v1alpha1

import (
	"net"

	"github.com/gardener/controller-manager-library/pkg/types"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const STATE_READY = "Ready"
const STATE_INVALID = "Invalid"
const STATE_BUSY = "Busy"
const STATE_DELETING = "Deleting"

const MODE_ROUNDROBIN = "RoundRobin"
const MODE_FIRSTMATCH = "FirstMatch" // default

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type IPAMRangeList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard list metadata
	// More info: http://releases.k8s.io/HEAD/docs/devel/api-conventions.md#metadata
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IPAMRange `json:"items"`
}

// +kubebuilder:storageversion
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,path=ipamranges,shortName=iprange,singular=ipamrange
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name=Mode,JSONPath=".spec.mode",type=string
// +kubebuilder:printcolumn:name=STATE,JSONPath=".status.state",type=string
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type IPAMRange struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              IPAMRangeSpec `json:"spec"`
	// +optional
	Status IPAMRangeStatus `json:"status,omitempty"`
}

type IPAMRangeSpec struct {
	// +optional
	Mode   string   `json:"mode,omitempty"`
	Ranges []string `json:"ranges"`

	// +optional
	ChunkSize int `json:"chunkSize, omitempty"`
}
type IPAMRangeStatus struct {
	types.StandardObjectStatus `json:",inline"`
	// + optional
	RoundRobin []string `json:"roundRobin,omitempty"`
}

func (this *IPAMRange) GetState() []net.IP {
	state := []net.IP{}
	for _, s := range this.Status.RoundRobin {
		_, cidr, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		ones, _ := cidr.Mask.Size()
		for len(state) <= ones {
			state = append(state, nil)
		}
		state[ones] = cidr.IP
	}
	return state
}
