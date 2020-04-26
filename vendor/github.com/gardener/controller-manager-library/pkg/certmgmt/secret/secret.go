/*
 * Copyright 2019 SAP SE or an SAP affiliate company. All rights reserved.
 * This file is licensed under the Apache Software License, v. 2 except as noted
 * otherwise in the LICENSE file
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

package secret

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/gardener/controller-manager-library/pkg/certmgmt"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/cluster"
	"github.com/gardener/controller-manager-library/pkg/fieldpath"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

const (
	// CAKeyName is the name of the CA private key
	CAKeyName = "ca-key.pem"
	// CACertName is the name of the CA certificate
	CACertName = "ca-certmgmt.pem"
	// KeyName is the name of the server private key
	KeyName = "key.pem"
	// CertName is the name of the serving certificate
	CertName = "certmgmt.pem"
)

var dataField = fieldpath.RequiredField(&corev1.Secret{}, ".Data")

type secretCertificateAccess struct {
	cluster cluster.Interface
	name    resources.ObjectName
}

var _ certmgmt.CertificateAccess = &secretCertificateAccess{}

func NewSecret(cluster cluster.Interface, name resources.ObjectName) certmgmt.CertificateAccess {
	return &secretCertificateAccess{
		cluster: cluster,
		name:    name,
	}
}

func (this *secretCertificateAccess) String() string {
	return fmt.Sprintf("{cluster: %s, secret: %s}", this.cluster.GetName(), this.name)
}

func (this *secretCertificateAccess) Get(logger logger.LogContext) (certmgmt.CertificateInfo, error) {

	secret, err := resources.GetSecret(this.cluster, this.name.Namespace(), this.name.Name())
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, err
		}
		return nil, nil
	}
	return dataToCertInfo(secret.GetData()), nil
}

func (this *secretCertificateAccess) Set(logger logger.LogContext, cert certmgmt.CertificateInfo) error {

	r, _ := this.cluster.GetResource(schema.GroupKind{corev1.GroupName, "Secret"})
	o := r.New(this.name)
	data := certInfoToData(cert)
	mod, err := resources.CreateOrModify(o, func(mod *resources.ModificationState) error {
		mod.Set(dataField, data)
		return nil
	})
	if mod {
		logger.Infof("certs in secret %q[%s] are updated", this.name, this.cluster.GetName())
	}
	return err
}

func dataToCertInfo(data map[string][]byte) certmgmt.CertificateInfo {
	if data == nil {
		return nil
	}
	_cert := data[CertName]
	_key := data[KeyName]
	_cacert := data[CACertName]
	_cakey := data[CAKeyName]

	return certmgmt.NewCertInfo(_cert, _key, _cacert, _cakey)
}

func certInfoToData(cert certmgmt.CertificateInfo) map[string][]byte {
	m := map[string][]byte{}
	add(m, CACertName, cert.CACert())
	add(m, CAKeyName, cert.CAKey())
	add(m, CertName, cert.Cert())
	add(m, KeyName, cert.Key())
	return m
}

func add(m map[string][]byte, key string, data []byte) {
	if len(data) > 0 {
		m[key] = data
	}
}
