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

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"time"

	v1alpha1 "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	scheme "github.com/mandelsoft/kubelink/pkg/client/kubelink/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// KubeLinksGetter has a method to return a KubeLinkInterface.
// A group's client should implement this interface.
type KubeLinksGetter interface {
	KubeLinks(namespace string) KubeLinkInterface
}

// KubeLinkInterface has methods to work with KubeLink resources.
type KubeLinkInterface interface {
	Create(*v1alpha1.KubeLink) (*v1alpha1.KubeLink, error)
	Update(*v1alpha1.KubeLink) (*v1alpha1.KubeLink, error)
	UpdateStatus(*v1alpha1.KubeLink) (*v1alpha1.KubeLink, error)
	Delete(name string, options *v1.DeleteOptions) error
	DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error
	Get(name string, options v1.GetOptions) (*v1alpha1.KubeLink, error)
	List(opts v1.ListOptions) (*v1alpha1.KubeLinkList, error)
	Watch(opts v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.KubeLink, err error)
	KubeLinkExpansion
}

// kubeLinks implements KubeLinkInterface
type kubeLinks struct {
	client rest.Interface
	ns     string
}

// newKubeLinks returns a KubeLinks
func newKubeLinks(c *KubelinkV1alpha1Client, namespace string) *kubeLinks {
	return &kubeLinks{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the kubeLink, and returns the corresponding kubeLink object, and an error if there is any.
func (c *kubeLinks) Get(name string, options v1.GetOptions) (result *v1alpha1.KubeLink, err error) {
	result = &v1alpha1.KubeLink{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("kubelinks").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of KubeLinks that match those selectors.
func (c *kubeLinks) List(opts v1.ListOptions) (result *v1alpha1.KubeLinkList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.KubeLinkList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("kubelinks").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested kubeLinks.
func (c *kubeLinks) Watch(opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("kubelinks").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch()
}

// Create takes the representation of a kubeLink and creates it.  Returns the server's representation of the kubeLink, and an error, if there is any.
func (c *kubeLinks) Create(kubeLink *v1alpha1.KubeLink) (result *v1alpha1.KubeLink, err error) {
	result = &v1alpha1.KubeLink{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("kubelinks").
		Body(kubeLink).
		Do().
		Into(result)
	return
}

// Update takes the representation of a kubeLink and updates it. Returns the server's representation of the kubeLink, and an error, if there is any.
func (c *kubeLinks) Update(kubeLink *v1alpha1.KubeLink) (result *v1alpha1.KubeLink, err error) {
	result = &v1alpha1.KubeLink{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("kubelinks").
		Name(kubeLink.Name).
		Body(kubeLink).
		Do().
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().

func (c *kubeLinks) UpdateStatus(kubeLink *v1alpha1.KubeLink) (result *v1alpha1.KubeLink, err error) {
	result = &v1alpha1.KubeLink{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("kubelinks").
		Name(kubeLink.Name).
		SubResource("status").
		Body(kubeLink).
		Do().
		Into(result)
	return
}

// Delete takes name of the kubeLink and deletes it. Returns an error if one occurs.
func (c *kubeLinks) Delete(name string, options *v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("kubelinks").
		Name(name).
		Body(options).
		Do().
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *kubeLinks) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	var timeout time.Duration
	if listOptions.TimeoutSeconds != nil {
		timeout = time.Duration(*listOptions.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("kubelinks").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Timeout(timeout).
		Body(options).
		Do().
		Error()
}

// Patch applies the patch and returns the patched kubeLink.
func (c *kubeLinks) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.KubeLink, err error) {
	result = &v1alpha1.KubeLink{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("kubelinks").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do().
		Into(result)
	return
}
