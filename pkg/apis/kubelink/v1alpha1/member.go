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

const STATE_OK = "Ok"

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type MeshMemberList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard list metadata
	// More info: http://releases.k8s.io/HEAD/docs/devel/api-conventions.md#metadata
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MeshMember `json:"items"`
}

// +kubebuilder:storageversion
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,path=meshmembers,shortName=mmembers,singular=mmember
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name=Identity,JSONPath=".spec.identity",type=string
// +kubebuilder:printcolumn:name=Address,JSONPath=".spec.clusterAddress",type=string
// +kubebuilder:printcolumn:name=CIDR,JSONPath=".spec.cidr",type=string
// +kubebuilder:printcolumn:name=Endpoint,JSONPath=".spec.endpoint",type=string
// +kubebuilder:printcolumn:name=State,JSONPath=".status.state",type=string
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type MeshMember struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              KubeLinkSpec `json:"spec"`
	// +optional
	Status MeshMemberStatus `json:"status,omitempty"`
}

type MeshMemberSpec struct {
	Identity       string `json:"identity"`
	ClusterAddress string `json:"clusterAddress"`
	// +optional
	Endpoint string `json:"endpoint"`
	// +optional
	CIDR string `json:"cidr"`

	// public key for wireguard
	// +optional
	PublicKey string `json:"publicKey,omitempty"`

	// +optional
	DNS *KubeLinkDNS `json:"dns,omitempty"`
}

type MeshMemberStatus struct {
	// +optional
	State string `json:"state,omitempty"`
	// +optional
	Message string `json:"message,omitempty"`
}
