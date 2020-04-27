/*
 * Copyright 2020 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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
