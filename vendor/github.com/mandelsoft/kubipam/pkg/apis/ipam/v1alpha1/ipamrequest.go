/*
 * Copyright 2019 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 *
 */

package v1alpha1

import (
	"github.com/gardener/controller-manager-library/pkg/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const STATE_ERROR = "Error"

//const STATE_INVALID = "Invalid"
const STATE_UP = "Up"

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type IPAMRequestList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard list metadata
	// More info: http://releases.k8s.io/HEAD/docs/devel/api-conventions.md#metadata
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IPAMRequest `json:"items"`
}

// +kubebuilder:storageversion
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,path=ipamrequests,shortName=ipreq,singular=ipamrequest
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name=IPAM,JSONPath=".spec.ipam.name",type=string
// +kubebuilder:printcolumn:name=Size,JSONPath=".spec.size",type=integer
// +kubebuilder:printcolumn:name=STATE,JSONPath=".status.state",type=string
// +kubebuilder:printcolumn:name=CIDR,JSONPath=".status.cidr",type=string
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type IPAMRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              IPAMRequestSpec `json:"spec"`
	// +optional
	Status IPAMRequestStatus `json:"status,omitempty"`
}

type IPAMRequestSpec struct {
	IPAM types.ObjectReference `json:"ipam"`
	// +optional
	Size int `json:"size,omitempty"`
	// +optional
	Description string `json:"description,omitempty"`
	// +optional
	Request string `json:"request,omitempty"` // not implemented yet - do not use
}

type IPAMRequestStatus struct {
	types.StandardObjectStatus `json:",inline"`

	// +optional
	CIDR string `json:"cidr,omitempty"`
}
