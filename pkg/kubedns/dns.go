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

package kubedns

import (
	"encoding/base64"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"gopkg.in/yaml.v2"
	_core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"

	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/kubelink"
	"github.com/mandelsoft/kubelink/pkg/tcp"
)

const CLUSTER_DNS_IP = 10
const KUBELINK_DNS_IP = 11

const DNSMODE_NONE = "none"
const DNSMODE_KUBERNETES = "kubernetes"
const DNSMODE_DNS = "dns"

type KubeDNS struct {
	config         *Config
	namespace      string
	secretResource resources.Interface
	links          *kubelink.Links
}

func NewKubeDNS(c controller.Interface) (*KubeDNS, error) {
	r, err := c.GetMainCluster().Resources().GetByExample(&_core.Secret{})
	if err != nil {
		return nil, fmt.Errorf("no secret resource found: %s", err)
	}
	cfg, err := c.GetOptionSource("kubedns")
	if err != nil {
		return nil, err
	}
	return &KubeDNS{
		config:         cfg.(*Config),
		namespace:      c.GetEnvironment().Namespace(),
		secretResource: r,
		links:          kubelink.GetSharedLinks(c),
	}, nil
}

func (this *KubeDNS) Links() *kubelink.Links {
	return this.links
}

func coreEntry(first *bool, name, basedomain string, dnsIP, clusterDomain string, local bool) string {
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
`, name, basedomain)

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
    forward . %s
`, name, basedomain, clusterDomain, escapedDomain, name, basedomain, dnsIP)
	} else {
		if local {
			plugin = fmt.Sprintf(`
    kubernetes %s.%s in-addr.arpa ip6.arpa {
        upstream
        fallthrough in-addr.arpa ip6.arpa
        ttl 30
    }
    forward . /etc/resolv.conf
`, name, basedomain)
		} else {
			plugin = fmt.Sprintf(`
    kubernetes %s.%s in-addr.arpa ip6.arpa {
        kubeconfig /etc/coredns/kubeconfig %s
        upstream
        fallthrough in-addr.arpa ip6.arpa
        ttl 30
    }
    forward . /etc/resolv.conf
`, name, basedomain, name)
		}
	}
	return header + plugin + footer
}

////////////////////////////////////////////////////////////////////////////////

func (this *KubeDNS) getSecretName(link *api.KubeLink) resources.ObjectName {
	if link.Spec.APIAccess == nil {
		return nil
	}
	ns := link.Spec.APIAccess.Namespace
	if ns == "" {
		ns = this.namespace
	}
	return resources.NewObjectName(ns, link.Spec.APIAccess.Name)
}

func (this *KubeDNS) getSecret(logger logger.LogContext, name resources.ObjectName) (resources.Object, *_core.Secret, error, error) {
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

func (this *KubeDNS) updateCorefile(logger logger.LogContext) {
	if this.config.DNSPropagation == DNSMODE_NONE {
		return
	}
	logger.Debug("update corefile")
	data := map[string][]byte{}

	first := true
	keys := []string{}

	kubeconfig := NewKubeconfig()
	if this.config.DNSPropagation == DNSMODE_KUBERNETES {

		this.Links().Visit(func(l *kubelink.Link) bool {
			if l.Token != "" {
				ip := tcp.SubIP(l.ServiceCIDR, 1)
				kubeconfig.AddCluster(l.Name, fmt.Sprintf("https://%s", ip), l.CACert, l.Token)
				keys = append(keys, l.Name)
			}
			return true
		})
	} else {
		this.Links().Visit(func(l *kubelink.Link) bool {
			keys = append(keys, l.Name)
			return true
		})
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
	if this.config.ClusterName != "" {
		clusterDomain := "cluster.local"
		if this.config.DNSPropagation == DNSMODE_DNS {
			if this.dnsInfo.DnsIP != nil {
				ip = this.dnsInfo.DnsIP.String()
			} else {
				ip = tcp.SubIP(this.config.ServiceCIDR, CLUSTER_DNS_IP).String()
			}
			if this.dnsInfo.ClusterDomain != "" {
				clusterDomain = this.dnsInfo.ClusterDomain
			}
		}
		corefile += coreEntry(&first, this.config.ClusterName, this.config.MeshDomain, ip, clusterDomain, true)
	}
	for _, k := range keys {
		clusterDomain := "cluster.local"
		l := this.Links().GetLink(k)
		if this.config.DNSPropagation == DNSMODE_DNS {
			if l.DnsIP != nil {
				ip = l.DnsIP.String()
			} else {
				ip = tcp.SubIP(l.ServiceCIDR, CLUSTER_DNS_IP).String()
			}
			if l.ClusterDomain != "" {
				clusterDomain = l.ClusterDomain
			}

		}
		corefile += coreEntry(&first, k, this.config.MeshDomain, ip, clusterDomain, false)
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
		logger.Infof("coredns secret %s updated", name)
		this.RestartDeployment(logger,
			resources.NewObjectName(this.Controller().GetEnvironment().Namespace(), this.config.CoreDNSDeployment))
	}
}

func (this *reconciler) updateLink(logger logger.LogContext, name string, access *kubelink.LinkAccessInfo, dns *kubelink.LinkDNSInfo) {
	_, err := this.linkResource.GetCached(resources.NewObjectName(name))
	if err != nil {
		logger.Infof("cannot get link %s: %s", name, err)
		return
	}
	_, mod := this.Links().UpdateLinkInfo(logger, name, access, dns, true)
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
