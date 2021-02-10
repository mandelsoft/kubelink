/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

package secret

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

type Keys struct {
	CAKeyName  string
	CACertName string
	KeyName    string
	CertName   string
}

func TLSKeys() Keys {
	return Keys{
		CAKeyName:  "ca.key",
		CACertName: "ca.crt",
		KeyName:    "tls.key",
		CertName:   "tls.crt",
	}
}

func DefaultKeys() Keys {
	return Keys{
		CAKeyName:  CAKeyName,
		CACertName: CACertName,
		KeyName:    KeyName,
		CertName:   CertName,
	}
}
