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

package broker

import (
	"encoding/base64"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"gopkg.in/yaml.v2"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	_core "k8s.io/api/core/v1"

	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/kubelink"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

const KUBELINK_DNS_IP = 11

type Manifest map[string]interface{}

type Kubeconfig Manifest

func NewKubeconfig() Kubeconfig {
	k := Kubeconfig{
		"apiVersion": "v1",
		"kind":       "Config",
		"clusters":   []Manifest{},
		"users":      []Manifest{},
		"contexts":   []Manifest{},
	}
	return k
}

func (this Kubeconfig) add(key string, entry Manifest) {
	this[key] = append(this[key].([]Manifest), entry)
}

func (this Kubeconfig) AddCluster(name, url, ca, token string) {
	this.add("clusters", Manifest{
		"name": name,
		"cluster": Manifest{
			"certificate-authority-data": Base64Encode([]byte(ca), 64),
			"server":                     url,
		},
	})
	this.add("users", Manifest{
		"name": name,
		"user": Manifest{
			"token": token,
		},
	})
	this.add("contexts", Manifest{
		"name": name,
		"context": Manifest{
			"user":    name,
			"cluster": name,
		},
	})
}

func coreEntry(first *bool, name, basedomain string, local bool) string {
	header := ""
	if *first {
		*first = false
		header = fmt.Sprintf(`
.:8053 {
    errors
    log . {
        class error
    }
    health
    ready
`)
	} else {
		header = fmt.Sprintf(`
%s.%s:8053 {
    errors
    log
`, name, basedomain)

	}
	footer := `
    forward . /etc/resolv.conf
    cache 30
    loop
    reload
    loadbalance round_robin
}

`
	plugin := ""
	if local {
		plugin = fmt.Sprintf(`
    kubernetes %s.%s in-addr.arpa ip6.arpa {
        upstream
        fallthrough in-addr.arpa ip6.arpa
        ttl 30
    }
`, name, basedomain)
	} else {
		plugin = fmt.Sprintf(`
    kubernetes %s.%s in-addr.arpa ip6.arpa {
        kubeconfig /etc/coredns/kubeconfig %s
        upstream
        fallthrough in-addr.arpa ip6.arpa
        ttl 30
    }
`, name, basedomain, name)
	}
	return header + plugin + footer
}

////////////////////////////////////////////////////////////////////////////////

func (this *reconciler) getSecretName(link *api.KubeLink) resources.ObjectName {
	if link.Spec.APIAccess == nil {
		return nil
	}
	ns := link.Spec.APIAccess.Namespace
	if ns == "" {
		ns = this.Controller().GetEnvironment().Namespace()
	}
	return resources.NewObjectName(ns, link.Spec.APIAccess.Name)
}

func (this *reconciler) getSecret(logger logger.LogContext, name resources.ObjectName) (resources.Object, *_core.Secret, error, error) {
	sobj, err := this.secretResource.GetCached(name)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil, nil, err
		}
		return nil, nil, err, nil
	}
	secret := sobj.Data().(*_core.Secret)
	return sobj, secret, nil, nil
}

func (this *reconciler) handleLinkAccess(logger logger.LogContext, klink *api.KubeLink, entry *kubelink.Link) (error, error) {
	if this.config.DNSPropagation {
		this.tasks.ScheduleTask(NewConnectTask(klink.Name, this), false)
	}
	if entry.UpdatePending {
		return this.updateSecretFromLink(logger, klink, entry)
	} else {
		return this.updateLinkFromSecret(logger, klink, entry)
	}
}

func (this *reconciler) updateLinkFromSecret(logger logger.LogContext, klink *api.KubeLink, entry *kubelink.Link) (error, error) {
	name := this.getSecretName(klink)

	if name == nil {
		return nil, nil
	}
	logger.Infof("handle api access for dns propagation of link %s evaluating secret %q", klink.Name, name)
	this.secrets.UpdateSecret(name, resources.NewObjectName(klink.Name))

	_, secret, terr, err := this.getSecret(logger, name)
	if terr != nil || err != nil {
		return terr, err
	}

	access := kubelink.LinkAccessInfo{}
	v := secret.Data["token"]
	if v != nil {
		access.Token = string(v)
	} else {
		err = fmt.Errorf("token missing in secret")
	}
	v = secret.Data["certificate-authority-data"]
	if v != nil {
		access.CACert = string(v)
	} else {
		err = fmt.Errorf("certificate-authority-data missing in secret")
	}
	this.Links().UpdateLinkAccess(logger, klink.Name, access, false)
	return nil, err
}

func (this *reconciler) updateSecretFromLink(logger logger.LogContext, klink *api.KubeLink, entry *kubelink.Link) (error, error) {
	if !this.config.DNSPropagation {
		return nil, nil
	}
	var secret *_core.Secret
	var sobj resources.Object
	var terr, err error

	if entry.Token == "" {
		return nil, nil
	}

	logger.Infof("persist pending link access info")
	create := false

	name := this.getSecretName(klink)
	if name == nil {
		create = true
		secret = &_core.Secret{
			TypeMeta: v1.TypeMeta{},
			ObjectMeta: v1.ObjectMeta{
				GenerateName: fmt.Sprintf("%s-", entry.Name),
				Namespace:    this.Controller().GetEnvironment().Namespace(),
			},
			Type: _core.SecretTypeOpaque,
		}
	} else {
		logger.Infof("found secret name %s for link %s", name, klink.Name)
		sobj, secret, terr, err = this.getSecret(logger, name)
		if terr != nil {
			return terr, err
		}
		if err != nil { // not found -> create it
			logger.Infof("requested secret not -> create it")
			secret = &_core.Secret{
				TypeMeta: v1.TypeMeta{},
				ObjectMeta: v1.ObjectMeta{
					Name:      name.Name(),
					Namespace: name.Namespace(),
				},
				Type: _core.SecretTypeOpaque,
			}
			create = true
		} else {
			secret = secret.DeepCopy()
		}
	}

	secretData := map[string][]byte{}
	secretData["token"] = []byte(entry.Token)
	if entry.CACert != "" {
		secretData["certificate-authority-data"] = []byte(entry.CACert)
	}
	secret.Data = secretData
	if create {
		sobj, err = this.secretResource.Create(secret)
		if err != nil {
			return fmt.Errorf("cannot create secret for link %q: err", entry.Name, err), nil
		}
		access := _core.SecretReference{
			Name:      sobj.GetName(),
			Namespace: sobj.GetNamespace(),
		}
		logger.Infof("created secret %s for link %s", access.Name, klink.Name)
		if name == nil {
			_, mod, err := this.linkResource.Modify(klink, func(data resources.ObjectData) (bool, error) {
				klink := data.(*api.KubeLink)
				if klink.Spec.APIAccess == nil {
					klink.Spec.APIAccess = &access
					logger.Infof("setting secret %s for link %s", access.Name, klink.Name)
					return true, nil
				}
				name = this.getSecretName(klink)
				return false, nil
			})
			if err != nil {
				sobj.Delete()
				return err, nil
			}
			if mod {
				this.Links().LinkAccessUpdated(logger, entry.Name, entry.LinkAccessInfo)
				return nil, nil
			}
			if !resources.EqualsObjectName(name, sobj.ObjectName()) {
				sobj.Delete()
				sobj, secret, terr, err = this.getSecret(logger, name)
				if terr != nil || err != nil {
					return terr, err
				}
			}
		}
	}

	_, err = sobj.Modify(func(data resources.ObjectData) (bool, error) {
		old := data.(*_core.Secret)
		mod := !reflect.DeepEqual(secretData, old.Data)
		if mod {
			old.Data = secretData
			logger.Infof("update secret for link %s", entry.Name)
		}
		return mod, nil
	})

	if err == nil {
		this.Links().LinkAccessUpdated(logger, entry.Name, entry.LinkAccessInfo)
	} else {
		logger.Errorf("cannot update secret: %s", err)
	}
	return err, nil
}

func (this *reconciler) updateCorefile(logger logger.LogContext) {
	if !this.config.DNSPropagation {
		return
	}
	logger.Debug("update corefile")
	first := true
	keys := []string{}
	kubeconfig := NewKubeconfig()

	this.Links().Visit(func(l *kubelink.Link) bool {
		if l.Token != "" {
			ip := tcp.CloneIP(l.ServiceCIDR.IP)
			ip[len(ip)-1] |= 1
			kubeconfig.AddCluster(l.Name, fmt.Sprintf("https://%s", ip), l.CACert, l.Token)
			keys = append(keys, l.Name)
		}
		return true
	})
	sort.Strings(keys)

	corefile := ""

	if this.config.ClusterName != "" {
		corefile += coreEntry(&first, this.config.ClusterName, this.config.MeshDomain, true)
	}
	for _, k := range keys {
		corefile += coreEntry(&first, k, this.config.MeshDomain, false)
	}

	b, err := yaml.Marshal(kubeconfig)

	if err != nil {
		logger.Errorf("cannot marshal kubeconfig: %s", err)
		return
	}
	data := map[string][]byte{
		"Corefile":   []byte(corefile),
		"kubeconfig": b,
	}

	name := resources.NewObjectName(this.Controller().GetEnvironment().Namespace(), this.config.CoreDNSSecret)
	_, mod, err := this.secretResource.CreateOrModifyByName(name,
		func(odata resources.ObjectData) (bool, error) {
			cur := odata.(*_core.Secret)
			if reflect.DeepEqual(cur.Data, data) {
				return false, nil
			}
			cur.Data = data
			return true, nil
		})

	if mod {
		logger.Infof("coredns secret %s updated", name)
		this.RestartDeployment(logger,
			resources.NewObjectName(this.Controller().GetEnvironment().Namespace(), this.config.CoreDNSDeployment))
	}
}

func (this *reconciler) updateLink(logger logger.LogContext, name string, access kubelink.LinkAccessInfo) {
	_, err := this.linkResource.GetCached(resources.NewObjectName(name))
	if err != nil {
		logger.Infof("cannot get link %s: %s", name, err)
		return
	}
	_, mod := this.Links().UpdateLinkAccess(logger, name, access, true)
	if mod {
		logger.Infof("link access for %s modified -> trigger link", name)
		this.TriggerUpdate()
		this.TriggerLink(name)
	}
}

func Base64Encode(data []byte, max int) string {
	str := base64.StdEncoding.EncodeToString(data)
	if max > 0 {
		result := ""
		for len(str) > max {
			result = result + str[:max] + "\n"
			str = str[max:]
		}
		if len(str) > 0 {
			result = result + str
		}
		if strings.HasSuffix(result, "\n") {
			result = result[:len(result)-1]
		}
		return result
	} else {
		return str
	}
}

func (this *reconciler) ConnectCoredns() {
	this.tasks.ScheduleTask(newConfigureCorednsTask(this), true)
}

type configureCorednsTask struct {
	BaseTask
	*reconciler
}

func newConfigureCorednsTask(reconciler *reconciler) Task {
	return &configureCorednsTask{
		BaseTask:   NewBaseTask("coredns", "configure"),
		reconciler: reconciler,
	}
}

func (this *configureCorednsTask) Execute(logger logger.LogContext) reconcile.Status {
	logger.Infof("configuring local cluster coredns setup to connect to mesh DNS")
	cm := &_core.ConfigMap{}
	name := resources.NewObjectName("kube-system", "coredns-custom")

	var ip net.IP

	if this.config.CoreDNSServiceIP == nil {
		if this.config.ServiceCIDR == nil {
			return reconcile.Failed(logger, fmt.Errorf("local service cidr or coredns ip required for establishing coredns connection"))
		}
		ip = tcp.CloneIP(this.config.ServiceCIDR.IP)
		ip[len(ip)-1] |= KUBELINK_DNS_IP
	} else {
		ip = this.config.CoreDNSServiceIP
	}
	_, err := this.Controller().GetMainCluster().Resources().GetObjectInto(name, cm)
	if err != nil {
		if !errors.IsNotFound(err) {
			return reconcile.Delay(logger, fmt.Errorf("cannot get coredns custom config: %s", err))
		}
		return reconcile.Delay(logger, fmt.Errorf("no coredns custom config found")).RescheduleAfter(10 * time.Minute)
	}

	config := fmt.Sprintf(`
%s:8053 {
	errors
	cache 30
	forward . %s
}
`, this.config.MeshDomain, ip)

	_, mod, err := this.Controller().GetMainCluster().Resources().ModifyObject(cm, func(data resources.ObjectData) (bool, error) {
		cm := data.(*_core.ConfigMap)
		if cm.Data["kubelink.server"] != config {
			cm.Data["kubelink.server"] = config
			this.Controller().Infof("updating coredns custom configuration")
			return true, nil
		}
		return false, nil
	})

	if mod {
		this.reconciler.RestartDeployment(logger, resources.NewObjectName("kube-system", "coredns"))
	}
	return reconcile.Succeeded(logger)
}
