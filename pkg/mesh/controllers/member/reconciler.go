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

package member

import (
	"fmt"
	"net"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile/reconcilers"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/gardener/controller-manager-library/pkg/types"
	ipamapi "github.com/mandelsoft/kubipam/pkg/apis/ipam/v1alpha1"
	"github.com/mandelsoft/kubipam/pkg/ipam"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/mandelsoft/kubelink/pkg/apis/kubelink/v1alpha1"
	"github.com/mandelsoft/kubelink/pkg/mesh/controllers"
	"github.com/mandelsoft/kubelink/pkg/mesh/database"
)

type reconciler struct {
	controllers.ReconcilerWithSlaves

	config   *Config
	database database.Meshes
	membres  resources.Interface
	ipamres  resources.Interface
	meshres  resources.Interface

	usageCache *reconcilers.SimpleUsageCache
}

var _ reconcile.Interface = &reconciler{}

type netinfo struct {
	size      int
	addr      net.IP
	cidr      *net.IPNet
	ipam      resources.Object
	confirmed string
}

func (this *netinfo) Version() string {
	if this.Size() == net.IPv4len {
		return "ipv4"
	}
	return "ipv6"
}

func (this *netinfo) Size() int {
	return this.size
}

func (this *netinfo) String() string {
	return fmt.Sprintf("%s %s %s", this.Version(), this.cidr, this.addr)
}

func NewNetInfo(ip net.IP) *netinfo {
	return &netinfo{size: len(ip), addr: ip}
}

///////////////////////////////////////////////////////////////////////////////

func (this *reconciler) Setup() error {
	res, err := this.Controller().GetMainCluster().GetResource(api.MEMBER)
	if err == nil {
		err = this.usageCache.SetupFilteredFor(this.Controller(), res, controllers.FilterMeshes,
			this.extractAndUpdateMesh)
	}
	if err == nil {
		err = this.usageCache.SetupFilteredFor(this.Controller(), res, controllers.FilterMembers,
			this.extractGateway)
	}
	return err
}

func (this *reconciler) Start() error {
	this.database.SetReady()
	return nil
}
func (this *reconciler) extractAndUpdateMesh(obj resources.Object) resources.ClusterObjectKeySet {
	this.Reconcile(this.Controller(), obj)
	return this.extractMesh(obj)
}

func (this *reconciler) extractMesh(obj resources.Object) resources.ClusterObjectKeySet {
	mesh := this.database.GetMeshByNamespace(obj.GetNamespace())
	if mesh == nil {
		return nil
	}
	return controllers.AsKeySet(mesh.GetClusterObjectKey())
}

func (this *reconciler) extractGateway(obj resources.Object) resources.ClusterObjectKeySet {
	member := obj.Data().(*api.MeshMember)
	if member.Spec.Gateway == nil {
		return nil
	}
	return controllers.AsKeySet(member.Spec.Gateway.ClusterKeyRelativeTo(obj, api.MEMBER))
}

///////////////////////////////////////////////////////////////////////////////

func (this *reconciler) Config() *Config {
	return this.config
}

func (this *reconciler) Reconcile(logger logger.LogContext, obj resources.Object) reconcile.Status {
	logger.Infof("reconcile")
	var err error
	var cfgerr error

	if obj.ObjectName().Name() == "kubelink1" {
		obj.ObjectName()
	}
	mesh := this.getMeshFor(obj.ClusterKey())
	if mesh == nil {
		return reconcile.UpdateStandardObjectStatusf(logger, obj, api.STATE_INVALID, "no mesh found for namespace %s", obj.GetNamespace())
	}

	member := obj.Data().(*api.MeshMember)

	old:=mesh.GetMemberById(member.Spec.Identity)
	if old!=nil && !database.EqualsObjectName(old.GetName().ObjectName(), obj.ObjectName()) {
		if obj.GetCreationTimestamp().After(old.GetCreationTimestamp()) {
			mesh.DeleteByName(obj.ObjectName())
			return reconcile.UpdateStandardObjectStatusf(logger, obj, api.STATE_INVALID, "duplicate identity with %q", old.GetName().Name())
		} else {
			mesh.DeleteByName(old.GetName().ObjectName())
		}
	}
	var info *netinfo
	a := member.Spec.Address
	if a != "" {
		ip := ipam.ParseIP(a)
		if ip == nil {
			return reconcile.UpdateStandardObjectStatusf(logger, obj, api.STATE_INVALID, "invalid ip address %s", a)
		}
		info = NewNetInfo(ip)
	}

	if mesh.GetState() != api.STATE_OK {
		return reconcile.UpdateStandardObjectStatusf(logger, obj, api.STATE_PENDING, mesh.GetMessage())
	}

	defer controllers.LockAndUpdateFilteredUsage(this.usageCache, obj.ClusterKey(), controllers.FilterMeshes, mesh.GetClusterObjectKey())()

	if member.Spec.Gateway != nil {
		gateway := member.Spec.Gateway.ClusterKeyRelativeTo(obj, api.MEMBER)
		defer controllers.LockAndUpdateFilteredUsage(this.usageCache, obj.ClusterKey(), controllers.FilterMembers, gateway)()
		_, err := this.membres.Get(gateway)
		if err != nil {
			if errors.IsNotFound(err) {
				return reconcile.UpdateStandardObjectStatusf(logger, obj, api.STATE_INVALID, "invalid gateway %q", gateway.Name())
			}
			return reconcile.Delay(logger, err)
		}
	}

	ipam := mesh.GetIPAM()
	if ipam == nil {
		return reconcile.Delay(logger, fmt.Errorf("waiting for ipam to be ready"))
	}
	reqs, err := this.LookupSlaves(obj.ClusterKey())
	if err != nil {
		return reconcile.Delay(logger, err)
	}

	err, cfgerr = this.checkNet(logger, &info, mesh)
	if cfgerr != nil {
		return reconcile.UpdateStandardObjectStatusf(logger, obj, api.STATE_INVALID, cfgerr.Error())
	}

	if err == nil {
		err = this.Controller().SetFinalizer(obj)
	}

	meshobj, err := this.Controller().GetObject(mesh.GetClusterObjectKey())
	if err != nil {
		return reconcile.Delay(logger, err)
	}
	logger.Infof("mesh %s now has %d members", mesh.GetName(), len(this.usageCache.GetFilteredUsersFor(mesh.GetClusterObjectKey(), controllers.FilterMembers)))

	if err == nil {
		err = this.Controller().SetFinalizer(meshobj)
	}
	if err != nil {
		reconcile.Delay(logger, err)
	}

	state := ""
	if err == nil {
		err, cfgerr, state = this.handleNet(logger, obj, reqs, info)
	}
	if cfgerr == nil {
		cfgerr = mesh.UpdateMember(obj)
		if cfgerr!=nil {
			state=api.STATE_INVALID
		}
	}
	if cfgerr != nil {
		mesh.DeleteByName(obj.ObjectName())
		return reconcile.UpdateStandardObjectStatus(logger, obj, state, cfgerr.Error())
	}
	if err == nil {
		_, err = this.CleanupObsoleteSlaves(logger, nil, reqs)
	}
	if err != nil {
		reconcile.Delay(logger, err)
	}
	addr := ""
	if info != nil && info.confirmed != "" {
		addr = info.confirmed
	}
	_, err = resources.ModifyStatus(obj, func(mod *resources.ModificationState) error {
		member := mod.Data().(*api.MeshMember)
		if mod.AssureStringValue(&member.Status.Address, addr).IsModified() {
			obj.Eventf(core.EventTypeNormal, "reconcile", "updated address to %s", addr)
			logger.Infof("updating address %s", addr)
		}
		return nil
	})
	if err != nil {
		return reconcile.Delay(logger, err)
	}
	return reconcile.UpdateStandardObjectStatusf(logger, obj, api.STATE_OK, "")
}

func (this *reconciler) checkNet(logger logger.LogContext, infop **netinfo, mesh database.Mesh) (error, error) {

	name := mesh.GetIPAM()
	if name == nil {
		return fmt.Errorf("ipman not yet set for mesh"), nil
	}
	ipam, err := this.ipamres.Get(name)
	if err != nil {
		return err, nil
	}
	size := net.IPv4len
	if mesh.GetCidr().IP.To4() == nil {
		size = net.IPv6len
	}
	info := &netinfo{size: size}
	if *infop != nil {
		info = *infop
	}

	cidr := mesh.GetCidr()
	info.cidr = cidr
	if info.addr != nil && !cidr.Contains(info.addr) {
		return nil, fmt.Errorf("invalid %s address %s: not in network cidr %s", info.Version(), info.addr, cidr)
	}

	info.ipam = ipam
	*infop = info
	return nil, nil
}

func (this *reconciler) handleNet(logger logger.LogContext, obj resources.Object, slaves controllers.Objects, info *netinfo) (error, error, string) {
	if info == nil {
		return nil, nil, ""
	}
	var err error
	vers := info.Version()
	reqs := controllers.ConsumeRequests(slaves, info.ipam)

	addr := ""
	if info.addr != nil {
		addr = info.addr.String()
	}
	if info.ipam != nil {
		var slave resources.Object

		if len(reqs) == 0 {
			i := &ipamapi.IPAMRequest{
				ObjectMeta: meta.ObjectMeta{
					GenerateName: fmt.Sprintf("%s-%s-", obj.GetName(), vers),
					Namespace:    obj.GetNamespace(),
				},
				Spec: ipamapi.IPAMRequestSpec{
					IPAM:        types.NewReferenceFrom(obj, info.ipam),
					Size:        info.Size() * 8,
					Description: fmt.Sprintf("%s IP request for member %s", vers, obj.ObjectName()),
					Request:     addr,
				},
			}
			slave, err = this.CreateSlave(obj, i)
			if err != nil {
				return err, nil, ""
			}
			if addr == "" {
				addr = "allocate"
			}
			obj.Eventf(core.EventTypeNormal, "reconcile", "created IPAMRequest %s (%s)", slave.ObjectName(), addr)
			logger.Infof("created %s IPAMRequest %s (%s)", info.Version(), slave.GetName(), addr)
		} else {
			slave, err = this.CleanupObsoleteSlaves(logger, &vers, reqs)
		}
		if err == nil {
			err = this.Controller().SetFinalizer(slave)
		}
		if err != nil {
			return err, nil, ""
		}
		if slave != nil {
			s := slave.Data().(*ipamapi.IPAMRequest)
			if s.Status.State != ipamapi.STATE_READY {
				if s.Status.State == "" {
					return nil, fmt.Errorf("%s IPAMRequest %s pending", info.Version(), s.Name), api.STATE_PENDING
				}
				return nil, fmt.Errorf("%s IPAMRequest %s not ready: %s", info.Version(), s.Name, s.Status.Message), api.STATE_ERROR
			}
			cidr, err := ipam.ParseCIDR(s.Status.CIDR)
			if err != nil {
				return nil, fmt.Errorf("malformed state of %s IPAMRequest %s : %s", info.Version(), s.Name, err), api.STATE_ERROR
			}
			info.confirmed = cidr.IP.String()
		}
	} else {
		info.confirmed = addr
	}
	return err, nil, ""
}

func (this *reconciler) cleanupHandler(logger logger.LogContext, obj resources.Object, okey resources.ClusterObjectKey) reconcile.Status {
	mesh := this.getMeshFor(okey)
	if mesh != nil {
		mesh.DeleteByName(okey.ObjectName())
	}
	status := controllers.CleanupMultiRefFinalizer(logger, this.Controller(), this.usageCache, obj, okey,
		controllers.FilterMembers, controllers.FilterMembers, this.extractGateway,
		"member", "gateway")
	if status.IsSucceeded() {
		status = controllers.CleanupMultiRefFinalizer(logger, this.Controller(), this.usageCache, obj, okey,
			controllers.FilterMembers, controllers.FilterMeshes, this.extractMesh,
			"member", "mesh")
	}
	return status
}

func (this *reconciler) getMeshFor(key resources.ClusterObjectKey) database.Mesh {
	return this.database.GetMeshByNamespace(key.Namespace())
}
