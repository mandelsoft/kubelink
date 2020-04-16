package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/mandelsoft/k8sbridge/pkg"
	"github.com/mandelsoft/k8sbridge/pkg/tunnel"
)

const name = "mytun"

type X struct {
	Y *Y `json:",inline,omitempty"`
}

type Y struct {
	A string `json:"a"`
}

func main() {
	if len(os.Args) < 2 {
		pkg.Error("interface required")
	}
	//pkg.ShowRoutes(os.Args[1])

	_, ipNet, _ := net.ParseCIDR("192.168.0.129/25")
	fmt.Printf("base: %s\n", tunnel.BroadcastAddress(*ipNet))

	x := X{
		Y: &Y{
			A: "test",
		},
	}

	s, _ := json.Marshal(&x)

	fmt.Printf("%s\n", s)
}
