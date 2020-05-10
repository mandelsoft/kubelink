
# A Network Bridge for Service Networks of Multiple Kubernetes Clusters

This projects implements a kubernetes controller manager that supports
VPN tunnels connecting the service networks of a mesh of kubernetes clusters.

The only precondition is, that these service networks are disjoint.
The connections to other clusters are just configured by a new custom resource.
Every connection is defined by a dedicated instance of this resource.
To establish a connection between two clusters both sides must provide an
appropriate link resource.

## Concept

Every kubernetes cluster that should participate in such a virtual service
network needs an own IP address in a network cidr defined for the mesh.
Like the service cidrs this network might be a private one, for example
192.168.0.0/24, which will offer the possibility to connect 253 clusters.
It must be disjoint from all node networks, pod networks and service networks
of all involved clusters. But the node and pod networks might be identical in
all clusters.

To connect the service networks of multiple clusters their service ip ranges
must be disjoint, for example 100.64.0.0/20, 100.64.0.16.0/20 and so on.

Every cluster participating in such a mesh requires an endpoint with an 
externally accessible
IP address with an assigned DNS name. This is typically achieved by defining
a kubernetes service of type `Loadbalancer`. The DNS name can automatically be 
provisioned by using the DNS controllers provided by the
[external-dns-management project](//github.com/gardener/external-dns-management)

The connection among the clusters is implemented by TLS secured TCP connections
maintained by the *kubelink-broker*. The required server certificate is taken
from a secret. It might best be maintained by an ACME-protocol based certificate
provider. For this the project 
[cert-management](//github.com/gardener/cert-management) can be used, which offers
a kubernetes controller manager working together with the above mentioned DNS
eco-system. 

The examples just provide such a setup.

Besides this connection management controller there is an additional controller
(*kubelink-router*) that manages the required routes on the cluster nodes.
Hereby the node where the broker is running is used as gateway.

On the gateway the broker maintains a tun device with the cidr of the cluster mesh
and the IP address assigned to the dedicated cluster. This address is also
used to provide an S-NAT for outgoing traffic to the other clusters. Depending
on the destination address the broker dials to the dedicated broker service
for this cluster. Therefore it uses its own server certificate as TLS client 
certificate. This way TLS is used for key exchange and no additional mechanism
is required. The common name of the client certificate (always the FQDN of the
external address of the broker for this cluster) is used to authenticate 
an incoming connection. It is guaranteed by the certificate authorithy that has
issued the server certificate.

The certificate, provate key and CA certificate is taken from a standard kubernetes
TLS secret. Here it is maintained by the certificate service, but it can also
be maintained manually.

The connections between two clusters can be configured dynamically just be adding
an instance of the *kubelink* custom resource.

```yaml
apiVersion: kubelink.mandelsoft.org/v1alpha1
kind: KubeLink
metadata:
  name: <remote cluster name>
spec:
  cidr: <service cidr of remote cluster>
  clusterAddress: <cidr notation of IP and netmask of the connected cluster in the cluster mesh network>
  endpoint: <the FQDN of the mesh endpoint of this cluster>
```

That's it, no certificate, no key, nothing else required in best case when
useing the DNS and server certificate provisioning controllers proposed above.

## Implementation

The two used controllers are bundled into one controller manager (`kubelink`)
using the [controllermanager-library](//github.com/gardener/controller-manager-library)
It is provided in a single image (see [Dockerfile](Dockerfile)). The example
manifests just choose the appropriate controller(s) by a dedicated command line option.

## Example

The folder `examples` contains the required manifests for two interconnected
clusters.

In your scenario you have to adapt some values accordingly. The assumptions 
here in the example files are:

Cluster mesh network cidr: 192.168.0.0/24

The sample clusters here were kindly provided by the [Gardener](//github.com/gardener/gardener) 
kubernetes fleet management environment. It supports the certificate and
DNS management out of the box, so the manifests can be used without installing
additional components.

| cluster name | kubelink1 | kubelink2 |
|---|---|---|
| node cidr | 10.250.0.0/16 | 10.250.0.0/16 |
| pod cidr | 100.96.0.0/11 | 100.96.0.0/11 |
| service cidr (disjoint) | 100.64.0.0/20 | 100.64.16.0/20 |
| cluster address and netmask | 192.168.0.11/24 | 192.168.0.12/24 |
| FQDN | kubelink.kubelink1.ringdev.shoot.dev.k8s-hana.ondemand.com | kubelink.kubelink1.ringdev.shoot.dev.k8s-hana.ondemand.com |

You can see, that the node and pod networks used in the involved clusters are identical.

On every cluster the kubelink service is deployed to the `kube-system` namespace,
but any other namespace is possible.

Here the [rbac roles and service account](examples/20-rbac.yaml) must be deployed. The 
[crd](examples/10-crds.yaml) will automatically be deployed by the controller manager
but can also be deployed manually (ATTENTION: no autdo update possible if manually deployed).

The [certificate request](examples/kubelink1/30-cert.yaml) is optional and is 
specific to the dedicated cluster. Here two folders are provided
`examples/kubelink1`and `examples/kubelink2` that contain the appriopriate example
files. 

The certificate requests work together with the DNS annotation of the kubernetes
services used by the [`kubelink-broker` deployments](examples/kubelink1/32-broker.yaml).
Finally the  [`kubelink-router` daemon sets](examples/kubelink1/31-router.yaml)
have to be deployed into the clusters.

Now the instrumentation is done and it is possible to define the mesh by applying 
the appropriate [`kubelink` resources](examples/kubelink1/40-kubelink2.yaml).
For every connection a pair of such instances have to be deployed into the
involved clusters.

### And now?

Now you can deploy a [service](examples/40-echo.yam) into one of the clusters,
for example `kubelink2`. The echo service from the examples just deploys a
tine http server echoing every request. It does neither offer a load balancer
nor an ingress, so it's a completely cluster-local service. Looking at the
service object you get a *ClusterIP* for this service, for example
100.64.22.1.

Now you can create a *busybox* pod 

```shell script
$ kubectl run -it --image busybox busybox --restart=Never
```

and call (replace by actual IP address)

```shell script
$ wget -O - 100.64.22.1
```

which reaches the provate echo service in the remote cluster.

## DNS Progation for Services

The broker supports the propagation of service DNS names. This is done
by an own `coredns` deployment, which is automatically configured
by the broker according to the established links and available API server access
information. The *coredns* DNS server is hereby configured with a separate
`kubernetes`plugin for every active foreign cluster and therefore needs access
to the foreign API servers. This connectivity is again done by the cluster mesh
access by using the service ip of the foreign cluster' API server
(service `kubernetes`)

The [coredns deployment](examples/kubelink1/50-coredns.yaml) is specific for
a dedicated cluster, because it contains
a dedicated service IP of the cluster (the cluster DNS service uses IP 10, and
the kubelink IP service is intended to use the IP 11 of the cluster's service
IP range)

This deployment provides an own DNS server serving the `kubelink.` domain
(default for option `--mesh-domain`). Every cluster of the mesh that
support the proliferation of service DNS entries is mapped to an own
sub domain, according to its cluster name (name of the `KubeLink` object).
Here the typical service structure is exposed
(&lt;*service*>.&lt;*namespace*>`.svc`).

This DNS server can be embedded into the local cluster DNS service by
reconfiguring the cluster DNS service.
For clusters using coreos this can easily be done
by configuring an own server in the `Corefile` forwarding the `kubelink.`domain
to the kubelink coredns service (therefore the fixed cluster IP from above
is used). This can be done for example by deploying a 
[`coredns-custom`](examples/kubelink1/51-forward.yaml) configmap.

There are serveral modes this DNS support can be used:

- *Explicit Configuration* of the DNS access information of the foreign clusters
  at the `KubeLink` objects.
  Here the spec field `apiAccess` has to be set to a valid secret
  reference. The secret must have the data fields:
  - `token` and 
  - `certificate-authority-data`
  taken from a service account of the foreign cluster with the appropriate
  permissions (see *kubeconfig plugin*)

- *Automatic Advertisement* of the DNS access info. Here the broker requires
  the option `--dns-advertisement`. The settings of the `KubeLink` objects are
  now maintained automatically by the broker according to information advertised
  by the foreign clusters.
  
  - With this option by the *Inbound Advertisement* is active.
    A precondition is that the foreign servers advertise their access information
    but the own information is not advertised
  - *Outbound Advertisement* is enabled by additionally setting the option 
    `--coredns-service-account`,  which must
    denote a service account whose credentials are used to advertise the DNS
    access info to foreign clusters. 
  
 
In all cases the option `--dns-propagation` must be set to enable the
DNS feature.  By default, only the foreign clusters are included in the mesh's
top-level domain. To provide a uniform DNS hierachy in all clusters of the
mesh inclusing the local cluster, the optional option `--cluster-name` can be
set, which provides a dedicated sub domain in the `kubelink.`top-level domain for
the local cluster.

A typical option set for the broker to enable the full service looks
like this (for the example cluster `kubelink1`):

```shell script
            - --dns-advertisement
            - --coredns-service-account=coredns
            - --dns-propagation
            - --cluster-name=kubelink1 # change-me
```

## Command Line Reference

```
Kubelink manages network links among kubernetes clusters

Usage:
  kubelink [flags]

Flags:
      --advertized-port int                         Advertized broker port for auto-connect
      --auto-connect                                Automatically register cluster for authenticated incoming requests
      --bind-address-http string                    HTTP server bind address
      --broker-port int                             Port for broker
      --broker.advertized-port int                  Advertized broker port for auto-connect of controller broker (default 80)
      --broker.auto-connect                         Automatically register cluster for authenticated incoming requests of controller broker
      --broker.broker-port int                      Port for broker of controller broker (default 8088)
      --broker.cacertfile string                    TLS ca certificate file of controller broker
      --broker.certfile string                      TLS certificate file of controller broker
      --broker.cluster-name string                  Name of local cluster in cluster mesh of controller broker
      --broker.coredns-deployment string            Name of coredns deployment used by kubelink of controller broker (default "kubelink-coredns")
      --broker.coredns-secret string                Name of dns secret used by kubelink of controller broker (default "kubelink-coredns")
      --broker.coredns-service-account string       Service Account to use for CoreDNS API Server Access of controller broker
      --broker.default.pool.size int                Worker pool size for pool default of controller broker (default 1)
      --broker.disable-bridge                       Disable network bridge of controller broker
      --broker.dns-advertisement                    Enable automatic advertisement of DNS access info of controller broker
      --broker.dns-name string                      DNS Name for managed certificate of controller broker
      --broker.dns-propagation                      Enable DNS Record propagation for Services of controller broker
      --broker.ifce-name string                     Name of the tun interface of controller broker
      --broker.ipip                                 enforce local routing over ip-ip tunnel of controller broker
      --broker.keyfile string                       TLS certificate key file of controller broker
      --broker.link-address string                  CIDR of cluster in cluster network of controller broker
      --broker.mesh-domain string                   Base domain for cluster mesh services of controller broker (default "kubelink")
      --broker.node-cidr string                     CIDR of node network of cluster of controller broker
      --broker.pool.resync-period duration          Period for resynchronization of controller broker
      --broker.pool.size int                        Worker pool size of controller broker
      --broker.secret string                        TLS secret of controller broker
      --broker.secret-manage-mode string            Manage mode for TLS secret of controller broker (default "none")
      --broker.secrets.pool.size int                Worker pool size for pool secrets of controller broker (default 1)
      --broker.served-links string                  Comma separated list of links to serve of controller broker (default "all")
      --broker.service string                       Service name for managed certificate of controller broker
      --broker.service-cidr string                  CIDR of of local service network of controller broker
      --broker.update.pool.resync-period duration   Period for resynchronization for pool update of controller broker (default 20s)
      --broker.update.pool.size int                 Worker pool size for pool update of controller broker (default 1)
      --cacertfile string                           TLS ca certificate file
      --certfile string                             TLS certificate file
      --cluster-name string                         Name of local cluster in cluster mesh
      --config string                               config file
  -c, --controllers string                          comma separated list of controllers to start (<name>,<group>,all) (default "all")
      --coredns-deployment string                   Name of coredns deployment used by kubelink
      --coredns-secret string                       Name of dns secret used by kubelink
      --coredns-service-account string              Service Account to use for CoreDNS API Server Access
      --cpuprofile string                           set file for cpu profiling
      --default.pool.size int                       Worker pool size for pool default
      --disable-bridge                              Disable network bridge
      --disable-namespace-restriction               disable access restriction for namespace local access only
      --dns-advertisement                           Enable automatic advertisement of DNS access info
      --dns-name string                             DNS Name for managed certificate
      --dns-propagation                             Enable DNS Record propagation for Services
      --grace-period duration                       inactivity grace period for detecting end of cleanup for shutdown
  -h, --help                                        help for kubelink
      --ifce-name string                            Name of the tun interface
      --ipip                                        enforce local routing over ip-ip tunnel
      --keyfile string                              TLS certificate key file
      --kubeconfig string                           default cluster access
      --kubeconfig.disable-deploy-crds              disable deployment of required crds for cluster default
      --kubeconfig.id string                        id for cluster default
      --lease-name string                           name for lease object
      --link-address string                         CIDR of cluster in cluster network
  -D, --log-level string                            logrus log level
      --maintainer string                           maintainer key for crds (defaulted by manager name)
      --mesh-domain string                          Base domain for cluster mesh services
      --name string                                 name used for controller manager
      --namespace string                            namespace for lease (default "kube-system")
  -n, --namespace-local-access-only                 enable access restriction for namespace local access only (deprecated)
      --node-cidr string                            CIDR of node network of cluster
      --omit-lease                                  omit lease for development
      --plugin-file string                          directory containing go plugins
      --pod-cidr string                             CIDR of pod network of cluster
      --pool.resync-period duration                 Period for resynchronization
      --pool.size int                               Worker pool size
      --router.default.pool.size int                Worker pool size for pool default of controller router (default 1)
      --router.ipip                                 enforce local routing over ip-ip tunnel of controller router
      --router.node-cidr string                     CIDR of node network of cluster of controller router
      --router.pod-cidr string                      CIDR of pod network of cluster of controller router
      --router.pool.resync-period duration          Period for resynchronization of controller router
      --router.pool.size int                        Worker pool size of controller router
      --router.update.pool.resync-period duration   Period for resynchronization for pool update of controller router (default 20s)
      --router.update.pool.size int                 Worker pool size for pool update of controller router (default 1)
      --secret string                               TLS secret
      --secret-manage-mode string                   Manage mode for TLS secret
      --secrets.pool.size int                       Worker pool size for pool secrets
      --served-links string                         Comma separated list of links to serve
      --server-port-http int                        HTTP server port (serving /healthz, /metrics, ...)
      --service string                              Service name for managed certificate
      --service-cidr string                         CIDR of local service network
      --update.pool.resync-period duration          Period for resynchronization for pool update
      --update.pool.size int                        Worker pool size for pool update
      --version                                     version for kubelink
```