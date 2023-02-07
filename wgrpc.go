package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"text/template"
)

const Path = "/etc/wireguard/"
const ListenOn = "localhost:9000"


var LocalStartFrom = net.IP{172, 22, 1, 1}

type Response struct {
	Ok     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	Object any    `json:"result,omitempty"`
}

type Peer struct {
	PublicKey string
	IPAddress net.IP
	Active    bool
}

type Wg struct {
	Id         int
	PublicKey  string
	IPAddress  net.IP
	Network    *net.IPNet
	IPNat      *net.IPNet
	Port       int
	Peers      []Peer
	PrivateKey string     `json:"-"`
	mu         sync.Mutex `json:"-"`
}

type Keypair struct {
	Private string
	Public  string
}

func (k *Keypair) public() {
	if len(k.Private) == 0 {
		return
	}
	var pubkey bytes.Buffer
	cmd := exec.Command("wg", "pubkey")
	reader, writer := io.Pipe()
	cmd.Stdin = reader
	cmd.Stdout = &pubkey
	gen := func(key []byte) {
		defer writer.Close()
		writer.Write(key)
	}
	go gen([]byte(k.Private))
	err := cmd.Run()
	if err != nil {
		fmt.Println(err.Error())
	}
	k.Public = strings.TrimSuffix(string(pubkey.Bytes()), "\n")
}

func (k *Keypair) new() {
	cmd := exec.Command("wg", "genkey")
	privkey, err := cmd.Output()
	if err != nil {
		fmt.Println(err.Error())
	}
	k.Private = strings.TrimSuffix(string(privkey), "\n")
	k.public()
}

func CopyOfIP(ip net.IP) net.IP {
	if ip.To4 == nil {
		return ip
	}
	var newip net.IP
	return append(newip, ip[len(ip)-4:]...)
}

func (w *Wg) storekeys() error {

	path := Path + "keys/" + strconv.Itoa(w.Id)
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		return err
	}
	priv, err := os.Create(path + "/privatekey")
	defer priv.Close()
	if err != nil {
		return err
	}
	_, err = priv.Write([]byte(w.PrivateKey))
	if err != nil {
		return err
	}
	pub, err := os.Create(path + "/publickey")
	defer pub.Close()
	if err != nil {
		return err
	}
	_, err = pub.Write([]byte(w.PublicKey))
	if err != nil {
		return err
	}
	return nil

}

func (w *Wg) keypair() error {
	var keypair Keypair
	keypair.new()
	if len(keypair.Private) == 0 || len(keypair.Public) == 0 {
		return errors.New("Cannot generate a pair of keys")
	}
	w.PrivateKey = keypair.Private
	w.PublicKey = keypair.Public
	err := w.storekeys()
	if err != nil {
		return err
	}
	return nil
}

func (w *Wg) reserveIPNet() error {
	f, err := os.Open(Path)
	if err != nil {
		return err
	}
	defer f.Close()

	files, err := f.Readdir(0)
	if err != nil {
		return err
	}
	unic := func(ip net.IP, addr []net.IPNet) bool {
		for _, net := range addr {
			if net.Contains(ip) {
				return false
			}
		}
		return true
	}
	scanif := func() []net.IPNet {
		var result []net.IPNet
		ifaces, err := net.Interfaces()
		if err != nil {
			fmt.Print(fmt.Errorf("localAddresses: %v\n", err.Error()))
		}
		for _, i := range ifaces {
			addrs, err := i.Addrs()
			if err != nil {
				fmt.Print(fmt.Errorf("localAddresses: %v\n", err.Error()))
				continue
			}
			for _, a := range addrs {
				ip, net, err := net.ParseCIDR(a.String())
				if err != nil {
					fmt.Println(err.Error())
				}
				if ip.To4 != nil {
					result = append(result, *net)

				}
			}
		}
		return result
	}

	incr := func(ip *net.IP) error {
		if (*ip)[2] < 254 {
			(*ip)[2]++

		} else {
			if (*ip)[1] < 30 {
				(*ip)[1]++
				(*ip)[2] = 1
			} else {
				return errors.New("No more availible ip addresses")
			}
		}
		(*ip)[3] = 1
		
		return nil
	}

	var addresses []net.IPNet
	addresses = append(addresses, scanif()...)
	for _, file := range files {
		var temp Wg
		name := file.Name()
		if strings.HasSuffix(name, ".conf") {
			ifname := regexp.MustCompile(`[0-9]{1,4}`).FindString(name)
			id, _ := strconv.Atoi(ifname)
			temp.Id = id
			if temp.Id == w.Id {
				continue
			}
			err = temp.readconf()
			if err != nil {
				return err
			}
			if temp.IPAddress.To4() == nil {
				continue
			}
			
			if unic(temp.IPAddress, addresses) {
				addresses = append(addresses, *temp.Network)
			}
		} else {
			
			continue
		}
	}

	w.IPAddress = net.IP{0, 0, 0, 0}
	w.IPAddress = CopyOfIP(LocalStartFrom)
	if len(addresses) > 0 {
		for unic(w.IPAddress, addresses) == false {
			incr(&w.IPAddress)
		}
	}
	w.Network = &net.IPNet{w.IPAddress.Mask(net.CIDRMask(24, 32)), net.IPMask{255, 255, 255, 0}}
	IPNat := CopyOfIP(w.IPAddress)
	IPNat = append(IPNat[:3], 128)
	w.IPNat = &net.IPNet{IPNat.Mask(net.CIDRMask(25, 32)), net.IPMask{255, 255, 255, 128}}

	return nil
}

func (w *Wg) readconf() error {

	f, err := os.Open(Path + "wg" + strconv.Itoa(w.Id) + ".conf")
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	var lines []string
	var buf []byte
	for scanner.Scan() {
		buf = scanner.Bytes()
		i := bytes.IndexByte(buf, byte('#'))
		if i != -1 {
			lines = append(lines, string(buf[:i]))
			continue
		}
		lines = append(lines, scanner.Text())

	}
	if err = scanner.Err(); err != nil {
		return err
	}
	getvalue := func(conf []string, field string) (string, error) {
		for _, line := range conf {
			if strings.HasPrefix(line, field) {
				kv := strings.SplitN(line, "=", 2)
				if len(kv) != 2 {
					return "", errors.New("Syntax error: Configuration file wg" + strconv.Itoa(w.Id) + ".conf has wrong string \"" + line + "\"")
				}
				return strings.TrimSpace(kv[1]), nil

			} else {
				continue
			}

		}
		return "", errors.New("Syntax error: Configuration file wg" + strconv.Itoa(w.Id) + ".conf has no field \"" + field + "\"")
	}

	value, err := getvalue(lines, "Address")
	if err != nil {
		return err
	}
	ip, network, err := net.ParseCIDR(value)
	if err != nil {
		return err
	}
	if ip.To4 != nil {
		w.IPAddress = ip
		w.Network = network

	}

	value, err = getvalue(lines, "ListenPort")
	if err != nil {
		return err
	}

	port, err := strconv.Atoi(value)
	if err != nil {
		return err
	}
	w.Port = port

	privkey, err := getvalue(lines, "PrivateKey")
	if err != nil {
		return err
	}
	w.PrivateKey = privkey

	peers := false
	var begin int
	var end int

	constructPeer := func(ls []string) (Peer, error) {
		var peer Peer
		key, err := getvalue(ls, "PublicKey")
		if err != nil {
			return peer, err
		}
		peer.PublicKey = key
		value, err := getvalue(ls, "AllowedIPs")
		if err != nil {
			return peer, err
		}
		ip, _, _ := net.ParseCIDR(value)
		if ip.To4 != nil {
			peer.IPAddress = ip
		}
		peer.Active = true
		return peer, nil

	}
	w.Peers = []Peer{}
	for i := 0; i < len(lines); i++ {

		if i == len(lines)-1 && peers == true {
			p, err := constructPeer(lines[begin:])
			if err != nil {
				return err
			}
			w.Peers = append(w.Peers, p)
			break
		}
		if strings.TrimSpace(lines[i]) == "[Peer]" {
			if peers == true {
				end = i - 1
				p, err := constructPeer(lines[begin:end])
				if err != nil {
					return err
				}
				w.Peers = append(w.Peers, p)
			}
			peers = true
			begin = i + 1
		}

	}

	return nil

}

func (w *Wg) getPrivateKey() error {
	f, err := os.Open(Path + "/keys/" + strconv.Itoa(w.Id) + "/privatekey")
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		w.PrivateKey = scanner.Text()
		return nil
	}
	return errors.New("Can not retrieve a private key for wg" + strconv.Itoa(w.Id))

}

func (w *Wg) getPublicKey() error {
	f, err := os.Open(Path + "/keys/" + strconv.Itoa(w.Id) + "/publickey")
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		w.PublicKey = scanner.Text()
		return nil
	}
	return errors.New("Can not retrieve a public key for wg" + strconv.Itoa(w.Id))

}

func (w *Wg) genconf() error {
	configfile, err := os.Create(Path + "wg" + strconv.Itoa(w.Id) + ".conf")
	defer configfile.Close()
	if err != nil {
		return err
	}

	funcMap := template.FuncMap{
		"IPAddress": func() string {
			net, _ := w.Network.Mask.Size()
			return w.IPAddress.String() + "/" + strconv.Itoa(net)
		},
		"NatRange": func() string {
			if w.IPNat == nil {
				ip := CopyOfIP(w.IPAddress)
				ip = append(ip[:3], 128)
				net := net.IPNet{net.IP(ip).Mask(net.CIDRMask(25, 32)), net.IPMask{255, 255, 255, 128}}
				return net.String()
			}
			return w.IPNat.String()

		},
	}

	raw := `[Interface]
PrivateKey = {{.PrivateKey}} 
Address = {{IPAddress}}
ListenPort = {{.Port}}
{{range .Peers}}
{{if .Active}}PostUp = iptables -t nat -A POSTROUTING -s {{.IPAddress}}/32 -j SNAT --to-source 88.99.36.168{{end}}{{end}}
{{range .Peers}}
{{if .Active}}PostDown = iptables -t nat -D POSTROUTING -s {{.IPAddress}}/32 -j SNAT --to-source 88.99.36.168{{end}}{{end}}
{{range .Peers}}
{{if .Active}}[Peer]
PublicKey = {{.PublicKey}}
AllowedIPs = {{.IPAddress}}/32{{end}}
{{end}}
`

	conf := bufio.NewWriter(configfile)

	tmpl, err := template.New("config").Funcs(funcMap).Parse(raw)
	if err != nil {
		fmt.Println(err.Error())
		return err
	}
	err = tmpl.Execute(conf, w)
	if err != nil {
		fmt.Println(err.Error())
		return err
	}

	if err != nil {
		fmt.Println(err.Error())
		return err
	}
	conf.Flush()
	return nil
}

func (w *Wg) New(id int, reply *Wg) error {
	if _, err := os.Stat(Path + "wg" + strconv.Itoa(id) + ".conf"); err == nil {
		return errors.New("Wg" + strconv.Itoa(id) + " is already exist")

	} else if errors.Is(err, os.ErrNotExist) {
		reply.Id = id
		err := reply.keypair()
		if err != nil {
			return err
		}
		reply.Port = 50000 + reply.Id
		w.mu.Lock()
		defer w.mu.Unlock()
		err = reply.reserveIPNet()
		if err != nil {
			return err
		}
		err = reply.genconf()
		if err != nil {
			return err
		}
		cmd := exec.Command("wg-quick", "up", "wg"+strconv.Itoa(id))
		cmd.Run()
		return nil

	} else {
		return err

	}
	return nil
}

func (w *Wg) Update(wg *Wg, reply *Response) error {
	
	if _, err := os.Stat(Path + "wg" + strconv.Itoa(wg.Id) + ".conf"); err == nil {
		cmd := exec.Command("wg-quick", "down", "wg"+strconv.Itoa(wg.Id))
		cmd.Run()
		err = wg.getPrivateKey()
		if err != nil {
			var temp Wg
			temp.Id = wg.Id
			if err = temp.readconf(); err == nil {
				wg.PrivateKey = temp.PrivateKey
				keys := Keypair{Private: wg.PrivateKey}
				keys.public()
				wg.PublicKey = keys.Public
				if len(wg.PrivateKey) == 0 || len(wg.PublicKey) == 0 {
					return errors.New("Can not retrieve a keypair")
				}
				err = wg.storekeys()
				if err != nil {
					return errors.New("Can not save keys to files: " + err.Error())
				}

			} else {
				return err
			}
		}
		err = wg.genconf()
		if err != nil {
			reply.Ok = false
			reply.Error = err.Error()
			return nil
		}
		cmd = exec.Command("wg-quick", "up", "wg"+strconv.Itoa(wg.Id))
		cmd.Run()

	} else {
		reply.Ok = false
		reply.Error = "Configuration file error: " + err.Error()
		return nil
	}
	reply.Ok = true
	return nil
}

func (w *Wg) Remove(id int, reply *Wg) error {

	cmd := exec.Command("wg-quick", "down", "wg"+strconv.Itoa(id))
	cmd.Run()

	if _, err := os.Stat(Path + "wg" + strconv.Itoa(id) + ".conf"); err == nil {
		reply.Id = id
		err = os.Remove(Path + "wg" + strconv.Itoa(id) + ".conf")
		if err != nil {
			return err
		}
		err = os.RemoveAll(Path + "keys/" + strconv.Itoa(id))
		if err != nil {
			return err
		}

	} else if errors.Is(err, os.ErrNotExist) {
		return errors.New("Wg" + strconv.Itoa(id) + " is not exist")

	} else {
		return err
	}
	return nil
}

func (w *Wg) Get(id int, reply *Wg) error {
	reply.Id = id
	err := reply.readconf()
	if err != nil {
		return err
	}
	var keys Keypair
	keys.Private = reply.PrivateKey
	keys.public()
	reply.PublicKey = keys.Public
	return nil
}

func (w *Wg) Keypair(args []any, reply *Keypair) error {
	reply.new()
	if len(reply.Private) == 0 || len(reply.Public) == 0 {
		return errors.New("Can not generate a pair of keys")
	}
	return nil
}

func (w *Wg) setkeys(k Keypair) {
	w.PublicKey = k.Public
	w.PrivateKey = k.Private
}

func main() {

	wg := new(Wg)
	rpc.Register(wg)
	tcpAddr, err := net.ResolveTCPAddr("tcp", ListenOn)
	checkError(err)

	listener, err := net.ListenTCP("tcp", tcpAddr)
	checkError(err)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		jsonrpc.ServeConn(conn)
	}

}

func checkError(err error) {
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(1)
	}
}
