
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
      --broker.default.pool.size int                Worker pool size for pool update of controller broker (default 1)
      --broker.dns-name string                      DNS Name for managed certificate of controller broker
      --broker.ifce-name string                     Name of the tun interface of controller broker
      --broker.keyfile string                       TLS certificate key file of controller broker
      --broker.link-address string                  CIDR of cluster in cluster network of controller broker
      --broker.node-cidr string                     CIDR of node network of cluster of controller broker
      --broker.pool.resync-period duration          Period for resynchronization of controller broker
      --broker.pool.size int                        Worker pool size of controller broker
      --broker.secret string                        TLS secret of controller broker
      --broker.secret-manage-mode string            Manage mode for TLS secret of controller broker (default "none")
      --broker.served-links string                  Comma separated list of links to serve of controller broker (default "all")
      --broker.service string                       Service name for managed certificate of controller broker
      --broker.service-cidr string                  CIDR of of local service network of controller broker
      --broker.update.pool.resync-period duration   Period for resynchronization for pool update of controller broker (default 20s)
      --broker.update.pool.size int                 Worker pool size for pool update of controller broker (default 1)
      --cacertfile string                           TLS ca certificate file
      --certfile string                             TLS certificate file
  -c, --controllers string                          comma separated list of controllers to start (<name>,<group>,all) (default "all")
      --cpuprofile string                           set file for cpu profiling
      --default.pool.size int                       Worker pool size for pool update
      --disable-namespace-restriction               disable access restriction for namespace local access only
      --dns-name string                             DNS Name for managed certificate
      --grace-period duration                       inactivity grace period for detecting end of cleanup for shutdown
  -h, --help                                        help for kubelink
      --ifce-name string                            Name of the tun interface
      --keyfile string                              TLS certificate key file
      --kubeconfig string                           default cluster access
      --kubeconfig.disable-deploy-crds              disable deployment of required crds for cluster default
      --kubeconfig.id string                        id for cluster default
      --lease-name string                           name for lease object
      --link-address string                         CIDR of cluster in cluster network
  -D, --log-level string                            logrus log level
      --maintainer string                           maintainer key for crds (defaulted by manager name)
      --name string                                 name used for controller manager
      --namespace string                            namespace for lease (default "kube-system")
  -n, --namespace-local-access-only                 enable access restriction for namespace local access only (deprecated)
      --node-cidr string                            CIDR of node network of cluster
      --omit-lease                                  omit lease for development
      --plugin-file string                          directory containing go plugins
      --pod-cidr string                             CIDR of pod network of cluster
      --pool.resync-period duration                 Period for resynchronization
      --pool.size int                               Worker pool size
      --router.default.pool.size int                Worker pool size for pool update of controller router (default 1)
      --router.node-cidr string                     CIDR of node network of cluster of controller router
      --router.pod-cidr string                      CIDR of pod network of cluster of controller router
      --router.pool.resync-period duration          Period for resynchronization of controller router
      --router.pool.size int                        Worker pool size of controller router
      --router.update.pool.resync-period duration   Period for resynchronization for pool update of controller router (default 20s)
      --router.update.pool.size int                 Worker pool size for pool update of controller router (default 1)
      --secret string                               TLS secret
      --secret-manage-mode string                   Manage mode for TLS secret
      --served-links string                         Comma separated list of links to serve
      --server-port-http int                        HTTP server port (serving /healthz, /metrics, ...)
      --service string                              Service name for managed certificate
      --service-cidr string                         CIDR of of local service network
      --update.pool.resync-period duration          Period for resynchronization for pool update
      --update.pool.size int                        Worker pool size for pool update
      --version                                     version for kubelink
```