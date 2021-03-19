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
	"github.com/gardener/controller-manager-library/pkg/utils"
	"gopkg.in/yaml.v2"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	_core "k8s.io/api/core/v1"

	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/controllers/broker/config"
	"github.com/mandelsoft/kubelink/pkg/kubelink"
	"github.com/mandelsoft/kubelink/pkg/tasks"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

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

func coreEntry(first *bool, kubekey, clusterName string, basedomain string, dnsIP, clusterDomain string, local bool) string {
	if !strings.HasSuffix(clusterDomain, ".") {
		clusterDomain += "."
	}
	escapedDomain := strings.Replace(clusterDomain, ".", `\.`, -1)
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
`, clusterName, basedomain)

	}
	footer := `
    cache 30
    loop
    reload
    loadbalance round_robin
}
`
	plugin := ""
	if dnsIP != "" {
		plugin = fmt.Sprintf(`
    rewrite name regex (.*)\.%s\.%s\. {1}.%s answer name (.*)\.%s {1}.%s.%s.
    forward . %s {
      except %s
    }
    template ANY ANY {
      rcode NXDOMAIN
    }
`, clusterName, basedomain, clusterDomain, escapedDomain, clusterName, basedomain, dnsIP, basedomain)
	} else {
		if local {
			plugin = fmt.Sprintf(`
    kubernetes %s.%s in-addr.arpa ip6.arpa {
        upstream
        fallthrough in-addr.arpa ip6.arpa
        ttl 30
    }
    forward . /etc/resolv.conf
`, clusterName, basedomain)
		} else {
			plugin = fmt.Sprintf(`
    kubernetes %s.%s in-addr.arpa ip6.arpa {
        kubeconfig /etc/coredns/kubeconfig %s
        upstream
        fallthrough in-addr.arpa ip6.arpa
        ttl 30
    }
    forward . /etc/resolv.conf
`, clusterName, basedomain, kubekey)
		}
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

func (this *reconciler) updateLinkFromObject(logger logger.LogContext, klink *api.KubeLink, entry *kubelink.Link) (error, error) {
	var access *kubelink.LinkAccessInfo
	var dnsInfo *kubelink.LinkDNSInfo
	var err error
	var terr error

	logger.Infof("update link from object")
	// API Access
	name := this.getSecretName(klink)
	if name != nil {
		var secret *_core.Secret

		logger.Infof("handle api access of link %s evaluating secret %q", klink.Name, name)
		this.secrets.UpdateSecret(name, resources.NewObjectName(klink.Name))
		_, secret, terr, err = this.getSecret(logger, name)
		if terr != nil || err != nil {
			return terr, err
		}

		access = &kubelink.LinkAccessInfo{}
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
	}

	if err == nil && klink.Spec.DNS != nil {
		// DNS Propagation
		dnsInfo = &kubelink.LinkDNSInfo{
			DNSPropagation: this.config.DNSPropagation != config.DNSMODE_NONE,
			ClusterDomain:  "cluster.local",
		}
		if klink.Spec.DNS.OmitDNSPropagation != nil {
			dnsInfo.DNSPropagation = !*klink.Spec.DNS.OmitDNSPropagation
		}
		if klink.Spec.DNS.BaseDomain != "" {
			dnsInfo.ClusterDomain = klink.Spec.DNS.BaseDomain
		}
		if klink.Spec.DNS.DNSIP != "" {
			ip := net.ParseIP(klink.Spec.DNS.DNSIP)
			if ip == nil {
				return nil, fmt.Errorf("invalid DNS IP Address (%s)", klink.Spec.DNS.DNSIP)
			}
			dnsInfo.DnsIP = ip
		} else {
			_, cidr, err := net.ParseCIDR(klink.Spec.CIDR)
			if err == nil {
				dnsInfo.DnsIP = tcp.SubIP(cidr, config.CLUSTER_DNS_IP)
			}
		}
	}
	if klink.Spec.Endpoint == kubelink.EP_LOCAL && dnsInfo == nil {
		dnsInfo = &kubelink.LinkDNSInfo{
			DNSPropagation: this.config.DNSPropagation != config.DNSMODE_NONE,
			ClusterDomain:  this.config.MeshDomain,
			DnsIP:          this.config.MeshDNSServiceIP,
		}
	}
	if dnsInfo != nil {
		logger.Infof("found dns info %s", dnsInfo)
	}

	this.Links().UpdateLinkInfo(logger, kubelink.DecodeLinkNameFromString(klink.Name), access, dnsInfo, false)
	return nil, err
}

func (this *reconciler) updateObjectFromLink(logger logger.LogContext, klink *api.KubeLink, entry *kubelink.Link) (error, error) {

	var secret *_core.Secret
	var sobj resources.Object
	var terr, err error

	_, _, err = this.linkResource.Modify(klink, func(data resources.ObjectData) (bool, error) {
		klink := data.(*api.KubeLink)
		mod := utils.ModificationState{}

		if entry.IsLocalLink() && entry.ServiceCIDR != nil {
			mod.AssureStringValue(&klink.Spec.CIDR, entry.ServiceCIDR.String())
		}
		if entry.DnsIP != nil || entry.ClusterDomain != "" || klink.Spec.DNS != nil {
			if entry.DnsIP != nil || entry.ClusterDomain != "" {
				if klink.Spec.DNS == nil {
					klink.Spec.DNS = &api.KubeLinkDNS{}
				}
				mod.AssureStringValue(&klink.Spec.DNS.DNSIP, entry.DnsIP.String())
				mod.AssureStringValue(&klink.Spec.DNS.BaseDomain, entry.ClusterDomain)
			} else {
				if klink.Spec.DNS.OmitDNSPropagation == nil {
					klink.Spec.DNS = nil
					mod.Modify(true)
				}
			}
		}
		return mod.IsModified(), nil
	})

	if err == nil && entry.Token != "" {
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
					this.Links().LinkInfoUpdated(logger, entry.Name, &entry.LinkAccessInfo, nil)
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

		if err != nil {
			logger.Errorf("cannot update secret: %s", err)
		}
	}
	if err == nil {
		this.Links().LinkInfoUpdated(logger, entry.Name, &entry.LinkAccessInfo, &entry.LinkDNSInfo)
	}
	return err, nil
}

func KubeKey(name kubelink.LinkName) string {
	if name.Mesh() == kubelink.DEFAULT_MESH {
		return name.Name()
	}
	return name.String()
}

func (this *reconciler) updateCorefile(logger logger.LogContext) {

	if this.config.DNSPropagation == config.DNSMODE_NONE {
		logger.Debugf("dns propagation disabled")
		return
	}
	log := utils.NewNotifier(logger)
	log.Debugf("update corefile")
	data := map[string][]byte{}

	first := true
	meshDomains := map[kubelink.LinkName]string{}
	keys := []string{}

	kubeconfig := NewKubeconfig()

	meshes := this.Links().GetMeshInfos()
	log.Debugf("found mesh domains: %s", utils.StringKeySet(meshes))

	for n, m := range meshes {
		if m.PropagateDNS() {
			log.Debugf("  handle mesh %q", n)
			this.Links().VisitLinks(func(l *kubelink.Link) bool {
				if l.MatchMesh(m.CIDR()) {
					if l.DNSPropagation {
						log.Debugf("  found matching link %s with dns propagation", l.Name)
						if this.config.DNSPropagation == config.DNSMODE_KUBERNETES {
							if l.Token != "" {
								ip := tcp.SubIP(l.ServiceCIDR, 1)
								kubeconfig.AddCluster(KubeKey(l.Name), fmt.Sprintf("https://%s", ip), l.CACert, l.Token)
								meshDomains[l.Name] = m.ClusterDomain()
								keys = append(keys, l.Name.String())
							}
						} else {
							meshDomains[l.Name] = m.ClusterDomain()
							keys = append(keys, l.Name.String())
						}
					} else {
						log.Debugf("  skip matching link %s without dns propagation", l.Name)
					}
				}
				return true
			})
		} else {
			log.Debugf("  dns progation disabled for mesh %q", n)
		}
	}
	b, err := yaml.Marshal(kubeconfig)
	if err != nil {
		logger.Errorf("cannot marshal kubeconfig: %s", err)
		return
	}
	data["kubeconfig"] = b
	sort.Strings(keys)

	corefile := ""
	ip := ""
	if this.config.DNSPropagation == config.DNSMODE_DNS {
		if this.dnsInfo.DnsIP != nil {
			ip = this.dnsInfo.DnsIP.String()
		} else {
			ip = tcp.SubIP(this.config.ServiceCIDR, config.CLUSTER_DNS_IP).String()
		}
		log.Debugf("using local dns servide %s", ip)
	}

	// handle local cluster for all meshes
	for n, m := range meshes {
		if m.PropagateDNS() {
			log.Debugf("creating local core entry for %s[%s]", n, m.ClusterName())
			corefile += coreEntry(&first, "", m.ClusterName(), m.ClusterDomain(), ip, this.dnsInfo.ClusterDomain, true)
		} else {
			log.Debugf("no local core entry for %s[%s]", n, m.ClusterName())
		}
	}

	// handle links for meshes
	log.Debugf("using dns propagation for %d links", len(keys))
	for _, k := range keys {
		name := kubelink.DecodeLinkNameFromString(k)
		ip := ""
		l := this.Links().GetLink(name)
		clusterDomain := "cluster.local"
		if l.ClusterDomain != "" {
			clusterDomain = l.ClusterDomain
		}
		if this.config.DNSPropagation == config.DNSMODE_DNS {
			if l.DnsIP != nil {
				ip = l.DnsIP.String()
			} else {
				ip = tcp.SubIP(l.ServiceCIDR, config.CLUSTER_DNS_IP).String()
			}
		}
		log.Debugf("create core entry for link %s mapping domain %s to %s [%s]", l.Name, clusterDomain, meshDomains[name], ip)
		corefile += coreEntry(&first, KubeKey(name), name.Name(), meshDomains[name], ip, clusterDomain, false)
	}
	data["Corefile"] = []byte(corefile)

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

	if err != nil {
		logger.Errorf("cannot update secret %s: %s", this.config.CoreDNSSecret, err)
		return
	}
	if mod {
		log.Infof("coredns secret %s updated", name)
		this.RestartDeployment(logger,
			resources.NewObjectName(this.Controller().GetEnvironment().Namespace(), this.config.CoreDNSDeployment))
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

func (this *reconciler) ConfigureCoredns() {

}
func (this *reconciler) ConnectCoredns() {
	this.tasks.ScheduleTask(newConfigureCorednsTask(this), 0)
}

////////////////////////////////////////////////////////////////////////////////

type configureCorednsTask struct {
	tasks.BaseTask
	*reconciler
}

func newConfigureCorednsTask(reconciler *reconciler) tasks.Task {
	return &configureCorednsTask{
		BaseTask:   tasks.NewBaseTask("coredns", "configure"),
		reconciler: reconciler,
	}
}

func (this *configureCorednsTask) Execute(logger logger.LogContext) reconcile.Status {
	log := utils.NewNotifier(logger, "configuring local cluster coredns setup to connect to mesh DNS")

	cm := &_core.ConfigMap{}
	name := resources.NewObjectName("kube-system", "coredns-custom")

	var ip net.IP
	if this.config.CoreDNSServiceIP == nil {
		if this.config.ServiceCIDR == nil {
			return reconcile.Failed(logger, fmt.Errorf("local service cidr or coredns ip required for establishing coredns connection"))
		}
		ip = tcp.CloneIP(this.config.ServiceCIDR.IP)
		ip[len(ip)-1] |= config.KUBELINK_DNS_IP
	} else {
		ip = this.config.CoreDNSServiceIP
	}
	log.Debugf("  using local mesh dns service %s", ip)

	_, err := this.Controller().GetMainCluster().Resources().GetObjectInto(name, cm)
	if err != nil {
		if !errors.IsNotFound(err) {
			return reconcile.Delay(logger, fmt.Errorf("cannot get coredns custom config: %s", err))
		}
		return reconcile.Delay(logger, fmt.Errorf("no coredns custom config found")).RescheduleAfter(10 * time.Minute)
	}

	config := ""
	meshes := this.Links().GetMeshInfos()
	keys := utils.StringKeySet(meshes).AsArray()
	sort.Strings(keys)
	log.Debugf("  found meshes %s", utils.StringKeySet(meshes))
	for _, k := range keys {
		m := meshes[k]
		if !m.PropagateDNS() {
			log.Debugf("  dns propagation disabled for %s", k)
			continue
		}
		meshforward := ""
		if m.DNSIP() != nil {
			log.Debugf("  propagate global mesh domain %s for %s to %s", m.ClusterDomain(), k, m.DNSIP())
			meshforward = fmt.Sprintf(`
svc.global.%s:8053 {
	errors
	cache 30
	forward . %s
}
`, m.ClusterDomain(), m.DNSIP())
		}
		log.Debugf("  propagate mesh domain %s for %s to local mesh dns %s", m.ClusterDomain(), k, ip)
		config += fmt.Sprintf(`
%s
%s:8053 {
	errors
	cache 30
	forward . %s
}
`, meshforward, m.ClusterDomain(), ip)
	}

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
		log.Infof("local cluster dns config updated")
		this.reconciler.RestartDeployment(logger, resources.NewObjectName("kube-system", "coredns"))
	}
	return reconcile.Succeeded(logger)
}
