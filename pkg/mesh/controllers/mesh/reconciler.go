/*
 * Copyright 2021 Mandelsoft. All rights reserved.
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

package mesh

import (
	"crypto/x509"
	"fmt"
	"net"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile/reconcilers"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	ipamapi "github.com/mandelsoft/kubipam/pkg/apis/ipam/v1alpha1"
	"github.com/mandelsoft/kubipam/pkg/ipam"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/mesh/controllers"
	"github.com/mandelsoft/kubelink/pkg/mesh/database"
)

var NamespaceGK = resources.NewGroupKind("", "Namespace")

type reconciler struct {
	controllers.ReconcilerWithSlaves
	config     *Config
	resc       resources.Interface
	usageCache *reconcilers.SimpleUsageCache

	database database.Meshes
}

func (this *reconciler) Setup() error {
	return reconcilers.ProcessResource(this.Controller(), "setup meshes", this.resc, func(logger logger.LogContext, obj resources.Object) (bool, error) {
		logger.Infof("setup mesh %q", obj.ObjectName())
		this.database.UpdateMesh(obj, nil, nil)
		return true, nil
	})
}

func (this *reconciler) extractSecret(obj resources.Object) resources.ClusterObjectKeySet {
	mesh := obj.Data().(*api.Mesh)
	if mesh.Spec.Secret == "" {
		return nil
	}
	return controllers.AsKeySet(controllers.ClusterObjectKey(mesh.Spec.Secret, controllers.SECRET, obj))
}

func (this *reconciler) Reconcile(logger logger.LogContext, obj resources.Object) reconcile.Status {
	logger.Infof("reconcile")
	mesh := obj.Data().(*api.Mesh)

	v4info, cfgerr := this.checkIPNet(logger, net.IPv4len, &mesh.Spec.Network)
	if cfgerr != nil {
		return reconcile.UpdateStandardObjectStatusf(logger, obj, api.STATE_INVALID, "invalid ipv4 spec: %s", cfgerr)
	}

	if mesh.Spec.Namespace == "" {
		_, err := resources.Modify(obj, func(m *resources.ModificationState) error {
			me := m.Data().(*api.Mesh)
			if m.Modify(me.Spec.Namespace == "").IsModified() {
				me.Spec.Namespace = obj.GetNamespace() + "-" + me.GetName()
			}
			mesh.Spec.Namespace = me.Spec.Namespace
			return nil
		})
		if err != nil {
			return reconcile.Delay(logger, err)
		}
	}

	_, secrets, err := controllers.UpdateMultiRefFinalizer(logger, this.Controller(), this.usageCache, obj, controllers.FilterMeshes, controllers.FilterSecrets, this.extractSecret, "mesh", "secret")
	if cfgerr != nil {
		return reconcile.Delay(logger, err)
	}

	var pool *x509.CertPool
	if len(secrets) > 0 {
		for _, s := range secrets {
			secret := s.Data().(*core.Secret)
			data := secret.Data["cacert"]
			if data != nil {
				pool, err = parseChain(data)
				if err != nil {
					return reconcile.UpdateStandardObjectStatusf(logger, obj, api.STATE_INVALID, "invalid certificate in secret %s", s.GetName())
				}
				logger.Infof("using local cert")
			} else {
				return reconcile.UpdateStandardObjectStatusf(logger, obj, api.STATE_INVALID, "no certificate (cacert) in secret %s", s.GetName())
			}
		}
	}
	ipams, err := this.LookupSlaves(obj.ClusterKey())
	if err == nil {
		err = this.Controller().SetFinalizer(obj)
	}
	if err == nil {
		var ns resources.Object
		ns, err = obj.Resources().GetObject(resources.NewKey(NamespaceGK, "", mesh.Spec.Namespace))
		if err != nil {
			if errors.IsNotFound(err) {
				ns, err = obj.Resources().CreateObject(&core.Namespace{
					ObjectMeta: meta.ObjectMeta{
						Name: mesh.Spec.Namespace,
						Labels: map[string]string{
							"workspace": mesh.Namespace,
							"mesh":      mesh.Name,
						},
						Finalizers: []string{
							this.Controller().FinalizerHandler().FinalizerName(obj),
						},
					},
				})
			}
			_ = ns
		}
	}
	if err == nil {
		var ipam resources.Object
		err, cfgerr, ipam = this.handleMesh(logger, obj, ipams, v4info)
		if ipam != nil {
			key := ipam.ClusterKey()
			this.database.UpdateMesh(obj, &key, pool)
		} else {
			this.database.UpdateMesh(obj, nil, pool)
		}
	}

	if cfgerr != nil {
		return reconcile.UpdateStandardObjectStatus(logger, obj, api.STATE_PENDING, cfgerr.Error())
	}
	if err == nil {
		_, err = this.CleanupObsoleteSlaves(logger, nil, ipams)
	}
	if err != nil {
		reconcile.Delay(logger, err)
	}

	return reconcile.UpdateStandardObjectStatusf(logger, obj, api.STATE_OK, "")
}

func (this *reconciler) checkIPNet(logger logger.LogContext, size int, spec *api.IPNet) (*netinfo, error) {
	if spec == nil {
		return nil, nil
	}
	if spec.CIDR == "" {
		return nil, fmt.Errorf("cidr missing")
	}
	_, cidr, err := net.ParseCIDR(spec.CIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid cidr: %s", err)
	}
	if ipam.CIDRBits(cidr) != net.IPv4len*8 {
		return nil, fmt.Errorf("%s is no IPv4 cidr", cidr)
	}
	if ipam.CIDRHostMaskSize(cidr) < 3 {
		return nil, fmt.Errorf("invalid cidr: too small")
	}

	var ranges ipam.IPRanges

	start := ipam.CIDRSubIP(cidr, 2)
	end := ipam.CIDRSubIPInt(cidr, ipam.CIDRHostSize(cidr).Sub(ipam.Int64(2)))
	if len(spec.IPAM.Ranges) > 0 {
		ranges, err = ipam.ParseIPRanges(spec.IPAM.Ranges...)
		if err != nil {
			return nil, fmt.Errorf("invalid ipam ranges: %s", err)
		}
	} else {
		ranges = append(ranges, &ipam.IPRange{
			Start: start,
			End:   end,
		})
	}

	for _, r := range ranges {
		if ipam.CIDRBits(cidr) != size*8 {
			if size == net.IPv4len {
				return nil, fmt.Errorf("%s is no IPv4 range", r)
			}
			return nil, fmt.Errorf("%s is no IPv6 range", r)
		}
		if ipam.IPCmp(r.Start, start) < 0 {
			return nil, fmt.Errorf("range %s not in network cidr range", r)
		}
		if ipam.IPCmp(end, r.End) < 0 {
			return nil, fmt.Errorf("range %s not in network cidr range", r)
		}
	}
	info := &netinfo{
		spec:   spec,
		cidr:   cidr,
		ranges: ranges,
	}
	logger.Infof("found %s", info)
	return info, nil
}

func (this *reconciler) handleMesh(logger logger.LogContext, obj resources.Object, slaves controllers.Objects, info *netinfo) (error, error, resources.Object) {
	if info == nil {
		return nil, nil, nil
	}
	var err error
	mesh := obj.Data().(*api.Mesh)
	vers := info.Version()
	ipams := controllers.ConsumeIPAMs(slaves, info.Size())

	var slave resources.Object

	if len(ipams) == 0 {
		l := []string{}
		for _, r := range info.ranges {
			l = append(l, r.String())
		}
		i := &ipamapi.IPAMRange{
			ObjectMeta: meta.ObjectMeta{
				GenerateName: fmt.Sprintf("%s-%s-", obj.GetName(), vers),
				Namespace:    mesh.Spec.Namespace,
			},
			Spec: ipamapi.IPAMRangeSpec{
				Mode:      ipamapi.MODE_ROUNDROBIN,
				ChunkSize: ipam.CIDRBits(info.cidr),
				Ranges:    l,
			},
		}
		slave, err = this.CreateSlave(obj, i)
		if err == nil {
			logger.Infof("created %s IPAMRange %s (%s)", vers, slave.GetName(), info.ranges)
			obj.Eventf(core.EventTypeNormal, "reconcile", "created IPAMRange %s", slave.ObjectName())
		}
	} else {
		slave, err = this.CleanupObsoleteSlaves(logger, &vers, ipams)
	}
	if err == nil {
		err = this.Controller().SetFinalizer(slave)
	}
	if err == nil && slave != nil {
		s := slave.Data().(*ipamapi.IPAMRange)
		if s.Status.State != ipamapi.STATE_READY {
			return nil, fmt.Errorf("%s IPAMRange %s not ready: %s", vers, s.Name, s.Status.Message), slave
		}
	}
	return err, nil, slave
}

func (this *reconciler) cleanupHandler(logger logger.LogContext, obj resources.Object, okey resources.ClusterObjectKey) reconcile.Status {
	if obj == nil {
		return reconcile.Succeeded(logger)
	}
	mesh := obj.Data().(*api.Mesh)

	if mesh.Namespace != "" {
		logger.Infof("cleanup namespace %q", mesh.Spec.Namespace)
		r, _ := obj.Resources().Get(NamespaceGK)
		nsname := resources.NewObjectName(mesh.Spec.Namespace)

		ns, err := r.Get(nsname)
		if err == nil {
			if ns.GetLabel("workspace") == obj.GetNamespace() && ns.GetLabel("mesh") == obj.GetName() {
				logger.Infof("deleting namespace %q", mesh.Spec.Namespace)
				err = this.Controller().RemoveFinalizer(ns)
				if err == nil {
					err = ns.Delete()
					if err == nil {
						_, err := r.Get(nsname)
						if err == nil {
							return reconcile.Delay(logger, fmt.Errorf("waiting for namespace to be deleted"))
						}
					}
				}
			} else {
				logger.Infof("namespace %q not managed", mesh.Spec.Namespace)
			}
		} else {
			if errors.IsNotFound(err) {
				err = nil
			}
		}
		if err != nil {
			return reconcile.Delay(logger, err)
		}
	}
	this.database.DeleteByName(obj.ObjectName())
	return controllers.CleanupMultiRefFinalizer(logger, this.Controller(), this.usageCache, obj, okey,
		controllers.FilterMeshes, controllers.FilterSecrets, this.extractSecret,
		"mesh", "secret")
}

func parseChain(data []byte) (*x509.CertPool, error) {
	if len(data) == 0 {
		return nil, nil
	}
	pool := x509.NewCertPool()
	ok := pool.AppendCertsFromPEM(data)
	if !ok {
		return nil, fmt.Errorf("invalid certificate")
	}
	return pool, nil
}
