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
	"k8s.io/apimachinery/pkg/util/intstr"
)

const STATE_OK = "Ok"                   // service configuration ok
const STATE_UNSUPPORTED = "Unsupported" // mesh services only supported in pod mode

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type MeshServiceList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard list metadata
	// More info: http://releases.k8s.io/HEAD/docs/devel/api-conventions.md#metadata
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MeshService `json:"items"`
}

// +kubebuilder:storageversion
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,path=meshservices,shortName=msvc,singular=meshservice
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name=Address,JSONPath=".spec.meshAddress",type=string
// +kubebuilder:printcolumn:name=Service,JSONPath=".spec.service",type=string
// +kubebuilder:printcolumn:name=Endpoints,JSONPath=".spec.endpoint",type=string
// +kubebuilder:printcolumn:name=State,JSONPath=".status.state",type=string
// +kubebuilder:printcolumn:name=Age,JSONPath=".metadata.creationTimestamp",type=date
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type MeshService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              MeshServiceSpec `json:"spec"`
	// +optional
	Status KubeLinkStatus `json:"status,omitempty"`
}

type MeshServiceSpec struct {
	// +optional
	MeshAddress string `json:"meshAddress,omitempty"`
	// +optional
	Mesh string `json:"mesh,omitempty"`
	// +optional
	Ports []ServicePort `json:"ports,omitempty"`
	// +optional
	Service string `json:"service,omitempty"`
	// +optional
	Endpoints []ServiceEndpoint `json:"endpoints,omitempty"`
}

type MeshServiceStatus struct {
	// +optional
	State string `json:"state,omitempty"`
	// +optional
	Message string `json:"message,omitempty"`
}

const PROTO_TCP = "TCP"
const PROTO_UDP = "UDP"

type ServicePort struct {
	// +optional
	Name string `json:"name,omitempty"`
	// +optional
	Protocol string `json:"protocol,omitempty"`
	Port     int32  `json:"port"`
}

type ServiceEndpoint struct {
	// +optional
	Address string `json:"address"`
	// +optional
	PortMappings []PortMapping `json:"portMappings"`
}

type PortMapping struct {
	// +optional
	Protocol   string             `json:"protocol,omitempty"`
	Port       intstr.IntOrString `json:"port"`
	TargetPort intstr.IntOrString `json:"targetPort"`
}
