/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
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

////////////////////////////////////////////////////////////////////////////////

var dataField = fieldpath.RequiredField(&corev1.Secret{}, ".Data")

type secretCertificateAccess struct {
	cluster cluster.Interface
	name    resources.ObjectName
	keys    []Keys
}

var _ certmgmt.CertificateAccess = &secretCertificateAccess{}

func NewSecret(cluster cluster.Interface, name resources.ObjectName, keys ...Keys) certmgmt.CertificateAccess {
	if len(keys) == 0 {
		keys = []Keys{DefaultKeys()}
	}
	return &secretCertificateAccess{
		cluster: cluster,
		name:    name,
		keys:    keys,
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
	return dataToCertInfo(secret.GetData(), this.keys), nil
}

func (this *secretCertificateAccess) Set(logger logger.LogContext, cert certmgmt.CertificateInfo) error {

	r, _ := this.cluster.GetResource(schema.GroupKind{corev1.GroupName, "Secret"})
	o := r.New(this.name)
	data := certInfoToData(cert, this.keys[0])
	mod, err := resources.CreateOrModify(o, func(mod *resources.ModificationState) error {
		mod.Set(dataField, data)
		return nil
	})
	if mod {
		logger.Infof("certs in secret %q[%s] are updated", this.name, this.cluster.GetName())
	}
	return err
}

func dataToCertInfo(data map[string][]byte, keys []Keys) certmgmt.CertificateInfo {
	if data == nil {
		return nil
	}
	var ok bool

	var _cert []byte
	for _, k := range keys {
		_cert, ok = data[k.CertName]
		if ok {
			break
		}
	}

	var _key []byte
	for _, k := range keys {
		_key, ok = data[k.KeyName]
		if ok {
			break
		}
	}

	var _cacert []byte
	for _, k := range keys {
		_cacert, ok = data[k.CACertName]
		if ok {
			break
		}
	}

	var _cakey []byte
	for _, k := range keys {
		_cakey, ok = data[k.CAKeyName]
		if ok {
			break
		}
	}

	return certmgmt.NewCertInfo(_cert, _key, _cacert, _cakey)
}

func certInfoToData(cert certmgmt.CertificateInfo, keys Keys) map[string][]byte {
	m := map[string][]byte{}
	add(m, keys.CACertName, cert.CACert())
	add(m, keys.CAKeyName, cert.CAKey())
	add(m, keys.CertName, cert.Cert())
	add(m, keys.KeyName, cert.Key())
	return m
}

func add(m map[string][]byte, key string, data []byte) {
	if len(data) > 0 {
		m[key] = data
	}
}
