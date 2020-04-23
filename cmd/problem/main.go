package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const TUNIP = "192.168.1.2"
const TUNCIDR = TUNIP + "/24"


func ExitOnErr(msg string, args ...interface{}) {
	if args[len(args)-1] == nil {
		return
	}
	fmt.Printf(msg+": %s\n", args...)
	os.Exit(1)
}

func echo(text string) {
	c := exec.Command("echo",  text)
	var out bytes.Buffer
	c.Stdout = &out
	c.Start()
	c.Wait()
	fmt.Printf("-> %s\n", out.String())
}

func cstringToGoString(cstring []byte) string {
	strs := bytes.Split(cstring, []byte{0x00})
	return string(strs[0])
}

type ifreq struct {
	name  [unix.IFNAMSIZ]byte // c string
	flags uint16                 // c short
	_pad  [24 - unsafe.Sizeof(uint16(0))]byte
}

func ioctl(fd, request uintptr, argp unsafe.Pointer) error {
	if _, _, e := syscall.Syscall6(syscall.SYS_IOCTL, fd, request, uintptr(argp), 0, 0, 0); e != 0 {
		return e
	}
	return nil
}

func createInterface(flags uint16, name string) (string, *os.File, error) {
	// Last byte of name must be nil for C string, so name must be
	// short enough to allow that
	if len(name) > syscall.IFNAMSIZ-1 {
		return "", nil, errors.New("device name too long")
	}

	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0600)
	if err != nil {
		return "", nil, err
	}

	var nbuf [syscall.IFNAMSIZ]byte
	copy(nbuf[:], []byte(name))

	fd := f.Fd()
	ifr := ifreq{
		name:  nbuf,
		flags: flags,
	}
	if err := ioctl(fd, syscall.TUNSETIFF, unsafe.Pointer(&ifr)); err != nil {
		return "", nil, err
	}
	return cstringToGoString(ifr.name[:]), f, nil
}

func main() {
	problem := len(os.Args) > 1 && os.Args[1]=="yes"

	if problem {
		echo("with problem")
	}

	name, fd, err:= createInterface(unix.IFF_TUN|unix.IFF_NO_PI, "")
	ExitOnErr("cannot create tun", err)
	fmt.Printf("tun: %s\n", name)

	if !problem {
		echo("without problem")
	}

	link, err := netlink.LinkByName(name)
	ExitOnErr("cannot get link %q", name, err)

	addr, err := netlink.ParseAddr(TUNCIDR)
	ExitOnErr("cannot create addr %q", TUNCIDR, err)

	err = netlink.AddrAdd(link, addr)
	ExitOnErr("cannot add addr %q", TUNCIDR, err)

	err = netlink.LinkSetUp(link)
	ExitOnErr("cannot bring up %q", name, err)


	wait := sync.WaitGroup{}
	wait.Add(1)

	go func() {
		buffer := [2000]byte{}
		for {
			n, err := fd.Read(buffer[:])  // booom
			if n <= 0 || err != nil {
				fmt.Printf("END: %d bytes, err=%s\n", n, err)
				break
			}
			log.Printf("Read %d bytes", n)
		}
		wait.Done()
	}()

	wait.Wait()
	log.Print("Closing")
	err = fd.Close()
	if err != nil {
		log.Print("Close errored: ", err)
	}
	log.Print("Exiting")
}
