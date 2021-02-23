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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const STATE_PENDING = "Pending"

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type MeshList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard list metadata
	// More info: http://releases.k8s.io/HEAD/docs/devel/api-conventions.md#metadata
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Mesh `json:"items"`
}

// +kubebuilder:storageversion
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,path=meshes,shortName=mesh,singular=mesh
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name=Identity,JSONPath=".spec.identity",type=string
// +kubebuilder:printcolumn:name=CIDR,JSONPath=".spec.network.cidr",type=string
// +kubebuilder:printcolumn:name=MeshNamespace,JSONPath=".spec.namespace",type=string
// +kubebuilder:printcolumn:name=Domain,JSONPath=".spec.domain",type=string
// +kubebuilder:printcolumn:name=State,JSONPath=".status.state",type=string
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type Mesh struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              MeshSpec `json:"spec"`
	// +optional
	Status MeshStatus `json:"status,omitempty"`
}

type MeshSpec struct {
	Identity string `json:"identity"`
	Network  IPNet  `json:"network"`
	Domain   string `json:"domain"`
	// +optional
	Namespace string `json:"namespace,omitempty"`
	// +optional
	Secret string `json:"secret,omitempty"`
}

type IPNet struct {
	CIDR string `json:"cidr"`
	IPAM *IPAM  `json:"ipam,omitempty"`
}

type IPAM struct {
	// +optional
	Ranges []string `json:"ranges,omitempty"`
}

type MeshStatus struct {
	// +optional
	State string `json:"state,omitempty"`
	// +optional
	Message string `json:"message,omitempty"`
}
