package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"sync"

	"github.com/coreos/go-iptables/iptables"

	"github.com/mandelsoft/k8sbridge/pkg"
	"github.com/mandelsoft/k8sbridge/pkg/play"
	"github.com/mandelsoft/k8sbridge/pkg/taptun"
)

const IPTAB = "nat"
const IPCHAIN = "POSTROUTING"

// Runs "iptables --version" to get the version string
func getIptablesVersionString(path string) (string, error) {
	//cmd := exec.Command(path, "--version")
	cmd := exec.Command("echo", "v1.6.0")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", err
	}
	return out.String(), nil
}

func x() *iptables.IPTables {

	/*
		path, err := exec.LookPath("iptables")
		if err != nil {
			return nil
		}

		vstring, err := getIptablesVersionString(path)
		if err != nil {
			return nil
		}
		return nil

		fmt.Printf("version %s\n", vstring)
	*/

	ipt, err := iptables.New()
	pkg.ExitOnErr("cannot create iptables access", err)
	return ipt
}

func main() {
	var ipt *iptables.IPTables
	tun, err := taptun.NewTun("")
	//name, fd, err:=taptun.CreateInterface(unix.IFF_TUN|unix.IFF_NO_PI, "")
	pkg.ExitOnErr("cannot create tun", err)
	fd := tun.ReadWriteCloser.(*os.File)
	name := tun.String()
	fmt.Printf("created %q\n", name)
	//defer tun.Close()

	ipt = x()
	if ipt != nil {
		rule := []string{"-o", tun.String(), "-j", "SNAT", "--to-source", play.TUNIP}
		ok, err := ipt.Exists(IPTAB, IPCHAIN, rule...)
		pkg.ExitOnErr("cannot check nat", err)
		if ok {
			fmt.Printf("nat rule %v already exists\n", rule)
		} else {
			// err = ipt.Append(IPTAB, IPCHAIN, rule...)
			pkg.ExitOnErr("cannot add nat rule %v", rule, err)
			fmt.Printf("added nat rule %v\n", rule)
		}
		defer func() {
			ipt.Delete(IPTAB, IPCHAIN, rule...)
		}()
	}

	play.ConfigureTun(name)

	/*
		link, err := netlink.LinkByName(tun.String())
		pkg.ExitOnErr("cannot get link %q", tun, err)

		addr, err := netlink.ParseAddr(TUNCIDR)
		pkg.ExitOnErr("cannot create addr %q", TUNCIDR, err)

		err = netlink.AddrAdd(link, addr)
		pkg.ExitOnErr("cannot add addr %q", TUNCIDR, err)

		err = netlink.LinkSetUp(link)
		pkg.ExitOnErr("cannot bring up %q", tun, err)

		_, dst, err := net.ParseCIDR(ROUTE)
		pkg.ExitOnErr("cannot parse cidr %q", ROUTE, err)
		route := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst}
		err = netlink.RouteAdd(route)
		pkg.ExitOnErr("cannot add route", err)

	*/
	/*
			ifce, err := net.InterfaceByName(tun.String())
			ExitOnErr("cannot get tun %q", tun, err)
			addrs, err := ifce.Addrs()

		ExitOnErr("cannot get addresses", err)

		fmt.Printf("MTU: %d, Flags: %s, Addr: %v\n", ifce.MTU, ifce.Flags, addrs)

		ShowRoutes(tun.String())
	*/

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		fmt.Printf("starting\n")
		fd.Fd()
		play.TraceTun(fd)
		wg.Done()
	}()
	wg.Wait()
}
