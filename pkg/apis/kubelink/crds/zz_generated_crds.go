/*
Copyright (c) 2020 Mandelsoft. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package crds

import (
	"github.com/gardener/controller-manager-library/pkg/resources/apiextensions"
	"github.com/gardener/controller-manager-library/pkg/utils"
)

var registry = apiextensions.NewRegistry()

func init() {
	var data string
	data = `

---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    controller-gen.kubebuilder.io/version: v0.2.9
  creationTimestamp: null
  name: kubelinks.kubelink.mandelsoft.org
spec:
  group: kubelink.mandelsoft.org
  names:
    kind: KubeLink
    listKind: KubeLinkList
    plural: kubelinks
    shortNames:
    - klink
    singular: kubelink
  scope: Cluster
  versions:
  - additionalPrinterColumns:
    - jsonPath: .spec.cidr
      name: CIDR
      type: string
    - jsonPath: .spec.clusterAddress
      name: Address
      type: string
    - jsonPath: .spec.endpoint
      name: Endpoint
      type: string
    - jsonPath: .status.gateway
      name: Gateway
      type: string
    - jsonPath: .status.state
      name: State
      type: string
    name: v1alpha1
    schema:
      openAPIV3Schema:
        properties:
          apiVersion:
            description: 'APIVersion defines the versioned schema of this representation of an object. Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources'
            type: string
          kind:
            description: 'Kind is a string value representing the REST resource this object represents. Servers may infer this from the endpoint the client submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds'
            type: string
          metadata:
            type: object
          spec:
            properties:
              apiAccess:
                description: SecretReference represents a Secret Reference. It has enough information to retrieve secret in any namespace
                properties:
                  name:
                    description: Name is unique within a namespace to reference a secret resource.
                    type: string
                  namespace:
                    description: Namespace defines the space within which the secret name must be unique.
                    type: string
                type: object
              cidr:
                type: string
              clusterAddress:
                type: string
              dns:
                properties:
                  baseDomain:
                    type: string
                  dnsIP:
                    type: string
                  omitDNSPropagation:
                    type: boolean
                type: object
              egress:
                items:
                  type: string
                type: array
              endpoint:
                type: string
              ingress:
                items:
                  type: string
                type: array
              publicKey:
                description: public key for wireguard
                type: string
            required:
            - clusterAddress
            - endpoint
            type: object
          status:
            properties:
              gateway:
                type: string
              message:
                type: string
              state:
                type: string
            type: object
        required:
        - spec
        type: object
    served: true
    storage: true
    subresources:
      status: {}
status:
  acceptedNames:
    kind: ""
    plural: ""
  conditions: []
  storedVersions: []
  `
	utils.Must(registry.RegisterCRD(data))
	data = `

---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    controller-gen.kubebuilder.io/version: v0.2.9
  creationTimestamp: null
  name: meshes.kubelink.mandelsoft.org
spec:
  group: kubelink.mandelsoft.org
  names:
    kind: Mesh
    listKind: MeshList
    plural: meshes
    shortNames:
    - mesh
    singular: mesh
  scope: Namespaced
  versions:
  - additionalPrinterColumns:
    - jsonPath: .spec.identity
      name: Identity
      type: string
    - jsonPath: .spec.network.cidr
      name: CIDR
      type: string
    - jsonPath: .spec.namespace
      name: MeshNamespace
      type: string
    - jsonPath: .spec.domain
      name: Domain
      type: string
    - jsonPath: .status.state
      name: State
      type: string
    name: v1alpha1
    schema:
      openAPIV3Schema:
        properties:
          apiVersion:
            description: 'APIVersion defines the versioned schema of this representation of an object. Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources'
            type: string
          kind:
            description: 'Kind is a string value representing the REST resource this object represents. Servers may infer this from the endpoint the client submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds'
            type: string
          metadata:
            type: object
          spec:
            properties:
              domain:
                type: string
              identity:
                type: string
              namespace:
                type: string
              network:
                properties:
                  cidr:
                    type: string
                  ipam:
                    properties:
                      ranges:
                        items:
                          type: string
                        type: array
                    type: object
                required:
                - cidr
                type: object
              secret:
                type: string
            required:
            - domain
            - identity
            - network
            type: object
          status:
            properties:
              message:
                type: string
              state:
                type: string
            type: object
        required:
        - spec
        type: object
    served: true
    storage: true
    subresources:
      status: {}
status:
  acceptedNames:
    kind: ""
    plural: ""
  conditions: []
  storedVersions: []
  `
	utils.Must(registry.RegisterCRD(data))
	data = `

---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    controller-gen.kubebuilder.io/version: v0.2.9
  creationTimestamp: null
  name: meshmembers.kubelink.mandelsoft.org
spec:
  group: kubelink.mandelsoft.org
  names:
    kind: MeshMember
    listKind: MeshMemberList
    plural: meshmembers
    shortNames:
    - mmembers
    singular: mmember
  scope: Namespaced
  versions:
  - additionalPrinterColumns:
    - jsonPath: .spec.identity
      name: Identity
      type: string
    - jsonPath: .spec.endpoint
      name: Endpoint
      type: string
    - jsonPath: .status.address
      name: Address
      type: string
    - jsonPath: .status.state
      name: State
      type: string
    - jsonPath: .spec.routes
      name: Routes
      priority: 2000
      type: string
    name: v1alpha1
    schema:
      openAPIV3Schema:
        properties:
          apiVersion:
            description: 'APIVersion defines the versioned schema of this representation of an object. Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources'
            type: string
          kind:
            description: 'Kind is a string value representing the REST resource this object represents. Servers may infer this from the endpoint the client submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds'
            type: string
          metadata:
            type: object
          spec:
            properties:
              address:
                type: string
              dns:
                properties:
                  baseDomain:
                    type: string
                  dnsIP:
                    type: string
                  omitDNSPropagation:
                    type: boolean
                type: object
              endpoint:
                additionalProperties:
                  type: string
                type: object
              gateway:
                description: ObjectReference is is plain reference to an object of an implicitly determined type
                properties:
                  clusterId:
                    type: string
                  name:
                    type: string
                  namespace:
                    type: string
                required:
                - name
                type: object
              identity:
                type: string
              publicKey:
                description: public key for wireguard
                type: string
              routes:
                items:
                  properties:
                    cidr:
                      type: string
                  required:
                  - cidr
                  type: object
                type: array
            required:
            - identity
            type: object
          status:
            properties:
              address:
                type: string
              message:
                type: string
              state:
                type: string
            type: object
        required:
        - spec
        type: object
    served: true
    storage: true
    subresources:
      status: {}
status:
  acceptedNames:
    kind: ""
    plural: ""
  conditions: []
  storedVersions: []
  `
	utils.Must(registry.RegisterCRD(data))
}

func AddToRegistry(r apiextensions.Registry) {
	registry.AddToRegistry(r)
}
