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
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const STATE_INVALID = "Invalid"   // Invalid because of erroneous link configuration
const STATE_STALE = "Stale"       // Invalid because problem in mesh setup
const STATE_UP = "Up"             // Link is up and connected
const STATE_IDLE = "Idle"         // Link ready for connections, but not yet active
const STATE_DOWN = "Down"         // Link is down because of unknown connectivity problem
const STATE_ERROR = "Error"       // Known error on connection
const STATE_DELETING = "Deleting" // (Mesh) Link is marked for deletion

const EP_INBOUND = "Inbound"

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type KubeLinkList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard list metadata
	// More info: http://releases.k8s.io/HEAD/docs/devel/api-conventions.md#metadata
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KubeLink `json:"items"`
}

// +kubebuilder:storageversion
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,path=kubelinks,shortName=klink,singular=kubelink
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name=CIDR,JSONPath=".spec.cidr",type=string
// +kubebuilder:printcolumn:name=Address,JSONPath=".spec.clusterAddress",type=string
// +kubebuilder:printcolumn:name=Endpoint,JSONPath=".spec.endpoint",type=string
// +kubebuilder:printcolumn:name=Gateway,JSONPath=".status.gateway",type=string
// +kubebuilder:printcolumn:name=State,JSONPath=".status.state",type=string
// +kubebuilder:printcolumn:name=Age,JSONPath=".metadata.creationTimestamp",type=date
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type KubeLink struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              KubeLinkSpec `json:"spec"`
	// +optional
	Status KubeLinkStatus `json:"status,omitempty"`
}

type KubeLinkSpec struct {
	// +optional
	CIDR string `json:"cidr"`
	// +optional
	Ingress []string `json:"ingress,omitempty"`
	// +optional
	Egress         []string `json:"egress,omitempty"`
	ClusterAddress string   `json:"clusterAddress"`

	// +optional
	Endpoint string `json:"endpoint,omitempty"`
	// +optional
	GatewayLink string `json:"gatewayLink,omitempty"`

	// public key for wireguard
	// +optional
	PublicKey string `json:"publicKey,omitempty"`
	// +optional
	PresharedKey string `json:"presharedKey,omitempty"`

	// +optional
	APIAccess *core.SecretReference `json:"apiAccess,omitempty"`
	// +optional
	DNS *KubeLinkDNS `json:"dns,omitempty"`
}

type KubeLinkDNS struct {
	// +optional
	OmitDNSPropagation *bool `json:"omitDNSPropagation,omitempty"`
	// IP Address of DNS Service. For LocalLinks this is the mesh global dns service
	// for regular links it is the link (cluster) dns service
	// +optional
	DNSIP string `json:"dnsIP,omitempty"`
	// Base DNS Domain. For LocalLinks this is the mesh domain, for regular
	// links it is the links local (cluster) domain
	// +optional
	BaseDomain string `json:"baseDomain,omitempty"`
}

type KubeLinkStatus struct {
	// +optional
	State string `json:"state,omitempty"`
	// +optional
	Message string `json:"message,omitempty"`
	// +optional
	Gateway string `json:"gateway,omitempty"`
	// +optional
	PublicKey string `json:"publicKey,omitempty"`
}
