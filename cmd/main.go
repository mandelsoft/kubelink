package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/mandelsoft/k8sbridge/pkg"
	"github.com/mandelsoft/k8sbridge/pkg/play"
	//"github.com/mandelsoft/k8sbridge/pkg/taptun"
	"github.com/pkg/taptun"
)

const TUNCIDR = play.TUNCIDR
const ROUTE = play.ROUTE

func configureO(name string) {
	c := exec.Command("sh", "-c", fmt.Sprintf("ip link set up cheese && ip a a %s dev cheese", TUNCIDR))
	c.Start()
	c.Wait()
}

func echo(name string) {
	c := exec.Command("echo",  fmt.Sprintf("ip link set up cheese && ip a a %s dev cheese", TUNCIDR))
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

func createInterfaceT(flags uint16, name string) (string, *os.File, error) {
	t, err:=taptun.NewTun(name)
	if err != nil {
	    return "", nil, err
	}

	fd:=t.ReadWriteCloser.(*os.File)
	fd.Fd()
	return t.String(), fd, err
}

func createInterface(flags uint16, name string) (string, *os.File, error) {
	fmt.Printf("using taptun\n")
	// Last byte of name must be nil for C string, so name must be
	// short enough to allow that
	if len(name) > unix.IFNAMSIZ-1 {
		return "", nil, errors.New("device name too long")
	}

	fd, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return "", nil, err
	}

	var nbuf [unix.IFNAMSIZ]byte
	copy(nbuf[:], []byte(name))
	ifr := ifreq{
		name:  nbuf,
		flags: flags,
	}

	var errno unix.Errno
	s, _ := fd.SyscallConn()
	s.Control(func(fd uintptr) {
		_, _, err = unix.Syscall(
			unix.SYS_IOCTL,
			fd,
			uintptr(unix.TUNSETIFF),
			uintptr(unsafe.Pointer(&ifr)),
		)
	})
	if errno != 0 {
		return "", nil, errno
	}
	fd.Fd()

	return cstringToGoString(ifr.name[:]), fd, nil
}

func createInterfaceO(flags uint16, name string) (string, *os.File, error) {
	// Last byte of name must be nil for C string, so name must be
	// short enough to allow that
	if len(name) > unix.IFNAMSIZ-1 {
		return "", nil, errors.New("device name too long")
	}

	fd, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		log.Fatal(err)
	}

	var ifr [unix.IFNAMSIZ + 64]byte
	copy(ifr[:], []byte(name))
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = flags

	var errno syscall.Errno
	s, _ := fd.SyscallConn()
	s.Control(func(fd uintptr) {
		_, _, errno = unix.Syscall(
			unix.SYS_IOCTL,
			fd,
			uintptr(unix.TUNSETIFF),
			uintptr(unsafe.Pointer(&ifr[0])),
		)
	})
	if errno != 0 {
		return "", nil, errno
	}
	return cstringToGoString(ifr[:unix.IFNAMSIZ]), fd, nil
}

func main() {

	name:= ""

	echo(name)
	name, fd, err:= createInterfaceO(unix.IFF_TUN|unix.IFF_NO_PI, name)
	pkg.ExitOnErr("cannot create tun", err)
	fmt.Printf("tun: %s\n", name)
	wait := sync.WaitGroup{}
	wait.Add(1)

	fd.Fd()
	play.ConfigureTun(name)
	go func() {
		play.TraceTun(fd)
		wait.Done()
	}()
	time.Sleep(time.Second * 30)
	log.Print("Closing")
	err = fd.Close()
	if err != nil {
		log.Print("Close errored: ", err)
	}
	wait.Wait()
	log.Print("Exiting")
}
