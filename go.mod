module github.com/mandelsoft/kubelink

go 1.15

//replace golang.zx2c4.com/wireguard/wgctrl => github.com/mandelsoft/wgctrl-go v0.0.0-20210208121059-d9ab8e5d81ee

require (
	github.com/ahmetb/gen-crd-api-reference-docs v0.2.0
	github.com/coreos/etcd v3.3.15+incompatible // indirect
	github.com/coreos/go-iptables v0.4.5
	github.com/gardener/controller-manager-library v0.2.1-0.20210331140137-3b24f1dd03d6
	github.com/mdlayher/ethernet v0.0.0-20190606142754-0394541c37b7
	github.com/onsi/ginkgo v1.14.0
	github.com/onsi/gomega v1.10.1
	github.com/pkg/errors v0.9.1 // indirect
	github.com/spf13/pflag v1.0.5
	github.com/vishvananda/netlink v1.1.1-0.20200221165523-c79a4b7b4066
	github.com/xlab/c-for-go v0.0.0-20201223145653-3ba5db515dcb // indirect
	golang.org/x/lint v0.0.0-20191125180803-fdd1cda4f05f
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	golang.org/x/sys v0.0.0-20201117222635-ba5294a509c7
	golang.zx2c4.com/wireguard v0.0.20201118 // indirect
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20200609130330-bd2cb7843e1b
	gopkg.in/yaml.v2 v2.3.0
	k8s.io/api v0.19.9
	k8s.io/apimachinery v0.19.9
	k8s.io/client-go v0.19.9
	k8s.io/code-generator v0.19.9
	k8s.io/kube-openapi v0.0.0-20200805222855-6aeccd4b50c6
	sigs.k8s.io/controller-tools v0.2.9
)
