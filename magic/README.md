
## Manifest Generation

Adapt the the `values.yaml` according to youre needs

- keep the member set generation and adapt constraints in `helper`
- or maintain the member list manually
- select runmode (wireguard/bridge) and podmode (true/false)
- just run `gen.sh` to generate the manifests for all mesh members

This requires the latest [spiff](https.//github.com/mandelsoft/spiff)
version v1.6.1 (not yet released).

