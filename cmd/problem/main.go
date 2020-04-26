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

var cmd = true

func echo(text string) {
	c := exec.Command("echo", text)
	if cmd {
		var out bytes.Buffer
		c.Stdout = &out
	}
	c.Start()
	c.Wait()
	if cmd {
		fmt.Printf("-> %s\n", c.Stdout)
	}

	if !cmd {
		var buf [1000]byte
		fd, err := os.Open("problem")
		ExitOnErr("cannot open", err)
		fd.Read(buf[:])
		fd.Close()
	}
}

func cstringToGoString(cstring []byte) string {
	strs := bytes.Split(cstring, []byte{0x00})
	return string(strs[0])
}

type ifreq struct {
	name  [unix.IFNAMSIZ]byte // c string
	flags uint16              // c short
	_pad  [24 - unsafe.Sizeof(uint16(0))]byte
}

func ioctl(fd, request uintptr, argp unsafe.Pointer) error {
	if _, _, e := syscall.Syscall(unix.SYS_IOCTL, fd, request, uintptr(argp)); e != 0 {
		return e
	}
	return nil
}

func createInterface(flags uint16, name string) (string, *os.File, error) {
	// Last byte of name must be nil for C string, so name must be
	// short enough to allow that
	if len(name) > unix.IFNAMSIZ-1 {
		return "", nil, errors.New("device name too long")
	}

	fd, err := unix.Open("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return "", nil, err
	}

	var nbuf [unix.IFNAMSIZ]byte
	copy(nbuf[:], []byte(name))

	ifr := ifreq{
		name:  nbuf,
		flags: flags,
	}
	//fd:=f.Fd()
	unix.SetNonblock(int(fd), true)
	if err := ioctl(uintptr(fd), syscall.TUNSETIFF, unsafe.Pointer(&ifr)); err != nil {
		return "", nil, err
	}
	unix.SetNonblock(int(fd), true)
	return cstringToGoString(ifr.name[:]), os.NewFile(uintptr(fd), "/dev/net/tun"), nil
}

func main() {
	problem := len(os.Args) > 1 && os.Args[1] == "yes"

	if problem {
		echo("with problem")
	}

	name, fd, err := createInterface(unix.IFF_TUN|unix.IFF_NO_PI, "")
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
			n, err := fd.Read(buffer[:]) // booom
			if n <= 0 || err != nil {
				fmt.Printf("END: %d bytes, err=%s", n, err)
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
