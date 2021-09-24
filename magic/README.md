
## Manifest Generation

Copy/sync this folder somewhere locally on your filesystem and
copy the `values.yaml` into your configuration directory.
Afterwards adapt the `settings` node of the copied `values.yaml`
according to your needs:

- keep the member set generation and adapt constraints in `settings.members`
  (it will generate a sequence of member entries with increasing ip
  addresses, indices and service ip ranges, the mesh service ip range will be
  split into consecutively 16 ranges)
- or maintain the `members` list manually
- select runmode (wireguard/bridge) and podmode (true/false)
- set foreign non-kubelink endpoints in node `external` or reset it to
  the empty list
- just run `gen.sh` from the copied `magic` folder in your config
  folder to generate the manifests for all mesh members
- there will be sub folders generated for every member containing all
  the required manifests

This requires the latest [spiff](https.//github.com/mandelsoft/spiff)
version [v1.7.0](https://github.com/mandelsoft/spiff/releases/tag/v1.7.0-beta-2).

Be sure to use a kuberbetes cluster with nodes featuring an image
supporting wireguard (for wireguard mode) and a calico with
auto detection method `cidr=10.250.0.0/16` (select your node IP range)

For gardener clusters this should be the default now.

**networking section in shoot.yaml**
```yaml
networking:
    type: calico
    providerConfig:
      apiVersion: calico.networking.extensions.gardener.cloud/v1alpha1
      kind: NetworkConfig
      backend: bird
      ipam:
        type: host-local
        cidr: usePodCIDR
      ipv4:
        autoDetectionMethod: cidr=10.250.0.0/16  # don't use the calico default method!!!!!
    pods: 100.96.0.0/11
    nodes: 10.250.0.0/16
    services: 100.64.0.0/20  # this must match your service ip range for your mesh members
```

**workers section: image gardenlinux at least version 247**
```
workers:
      - name: worker-mkxlm
        machine:
          type: m5.large
          image:
            name: gardenlinux
            version: 318.8.0
        maximum: 2
        minimum: 2
        maxSurge: 1
        maxUnavailable: 0
        volume:
          type: gp2
          size: 50Gi
        zones:
          - eu-north-1b
        systemComponents:
          allow: true
```



