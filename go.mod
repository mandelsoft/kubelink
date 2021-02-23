module github.com/mandelsoft/kubelink

go 1.15

replace golang.zx2c4.com/wireguard/wgctrl => github.com/mandelsoft/wgctrl-go v0.0.0-20210208121059-d9ab8e5d81ee

require (
	github.com/ahmetb/gen-crd-api-reference-docs v0.2.0
	github.com/coreos/go-iptables v0.4.5
	github.com/gardener/controller-manager-library v0.2.1-0.20210303142856-b0163328fbbd
	github.com/mandelsoft/kubipam v0.0.0-20200702084454-32aad3c69d22
	github.com/mdlayher/ethernet v0.0.0-20190606142754-0394541c37b7
	github.com/onsi/ginkgo v1.14.0
	github.com/onsi/gomega v1.10.1
	github.com/pkg/errors v0.9.1
	github.com/spf13/pflag v1.0.5
	github.com/vishvananda/netlink v1.1.1-0.20200221165523-c79a4b7b4066
	github.com/xlab/c-for-go v0.0.0-20201223145653-3ba5db515dcb // indirect
	golang.org/x/lint v0.0.0-20190313153728-d0100b6bd8b3
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	golang.org/x/sys v0.0.0-20201117222635-ba5294a509c7
	golang.zx2c4.com/wireguard v0.0.20201118 // indirect
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-00010101000000-000000000000
	gopkg.in/yaml.v2 v2.3.0
	k8s.io/api v0.18.6
	k8s.io/apimachinery v0.18.6
	k8s.io/client-go v0.18.6
	k8s.io/code-generator v0.18.6
	k8s.io/kube-openapi v0.0.0-20200410145947-61e04a5be9a6
	sigs.k8s.io/controller-tools v0.2.9
)
