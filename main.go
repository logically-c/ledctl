package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/phayes/freeport"
	"github.com/subchen/go-cli"
)

func main() {

	app := cli.NewApp()
	app.Name = "ledctl"
	app.Usage = "An interface for controlling Magic Home RGB LEDs"
	app.Version = "1.0.0"
	app.Commands = []*cli.Command{
		{
			Name:  "set-wifi",
			Usage: "Configure the LED controller's wifi network",
			Flags: []*cli.Flag{
				{
					Name:  "ip",
					Usage: "ip address of the LED controller",
				},
				{
					Name:  "ssid",
					Usage: "ssid of the wifi network to connect to",
				},
				{
					Name:  "password",
					Usage: "password of the wifi network to connect to",
				},
				{
					Name:  "mode",
					Usage: "wifi security mode (OPEN, SHARED, WPAPSK)",
				},
				{
					Name:  "algo",
					Usage: "encryption algorithm used (NONE, WEP, TKIP, AES)",
				},
			},
			Action: func(c *cli.Context) {
				if c.GetString("ip") == "" {
					log.Fatal("--ip is required")
					os.Exit(1)
				}

				if c.GetString("ssid") == "" {
					log.Fatal("--ssid is required")
					os.Exit(1)
				}

				if c.GetString("password") == "" {
					log.Fatal("--password is required")
					os.Exit(1)
				}

				if c.GetString("mode") == "" {
					log.Fatal("--mode is required")
					os.Exit(1)
				}

				if c.GetString("algo") == "" {
					log.Fatal("--algo is required")
					os.Exit(1)
				}

				err := setWifi(c.GetString("ip"), c.GetString("ssid"), c.GetString("password"), c.GetString("mode"), c.GetString("algo"))
				if err != nil {
					log.Fatal(err)
					os.Exit(1)
				}
			},
		},
		{
			Name:  "set-color",
			Usage: "Set the color of the LEDs. Expects RR GG BB values as hex.",
			Flags: []*cli.Flag{
				{
					Name:  "ip",
					Usage: "ip address of the LED controller",
				},
			},
			Action: func(c *cli.Context) {
				if len(c.Args()) != 3 {
					log.Println("USAGE: ledctl set-color RR GG BB")
					os.Exit(1)
				}

				r, err := strconv.ParseInt(c.Arg(0), 16, 64)
				g, err := strconv.ParseInt(c.Arg(1), 16, 64)
				b, err := strconv.ParseInt(c.Arg(2), 16, 64)

				err = setColor(c.GetString("ip"), int(r), int(g), int(b))

				if err != nil {
					log.Fatal(err)
					os.Exit(1)
				}
			},
		},
		{
			Name:  "power-on",
			Usage: "Turn the unit on",
			Flags: []*cli.Flag{
				{
					Name:  "ip",
					Usage: "ip address of the LED controller",
				},
			},
			Action: func(c *cli.Context) {
				err := powerOn(c.GetString("ip"))
				if err != nil {
					log.Fatal(err)
					os.Exit(1)
				}
			},
		},
		{
			Name:  "power-off",
			Usage: "Turn the unit off",
			Flags: []*cli.Flag{
				{
					Name:  "ip",
					Usage: "ip address of the LED controller",
				},
			},
			Action: func(c *cli.Context) {
				err := powerOff(c.GetString("ip"))
				if err != nil {
					log.Fatal(err)
					os.Exit(1)
				}
			},
		},
		{
			Name:  "http",
			Usage: "Start an HTTP API server",
			Flags: []*cli.Flag{
				{
					Name:  "p, port",
					Usage: "Port to run the server on",
				},
			},
			Action: startHTTP,
		},
	}

	app.Run(os.Args)

}

type connection struct {
	localIPAddress  string
	localPort       int
	remoteIPAddress string
	remotePort      int
}

func newConnection(remoteIP string, remotePort int) *connection {
	if remoteIP == "" {
		log.Println("IP Address required (--ip 0.0.0.0)")
		os.Exit(1)
	}

	ip, err := getLocalIP()
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	port, err := freeport.GetFreePort()
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	return &connection{
		localIPAddress:  ip,
		localPort:       port,
		remoteIPAddress: remoteIP,
		remotePort:      remotePort,
	}
}

func setWifi(ip string, ssid string, password string, mode string, algo string) error {
	localIP, err := getLocalIP()
	if err != nil {
		return err
	}

	localAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%v", localIP, 48899))
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp", localAddr, &net.UDPAddr{
		Port: 48899,
		IP:   net.ParseIP(ip),
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(conn, "HF-A11ASSISTHREAD\r")
	time.Sleep(2 * time.Second)
	fmt.Fprintf(conn, "+ok")
	time.Sleep(2 * time.Second)
	fmt.Fprintf(conn, fmt.Sprintf("AT+WSSSID=%s\r", ssid))
	time.Sleep(2 * time.Second)
	fmt.Fprintf(conn, fmt.Sprintf("AT+WSKEY=%s,%s,%s\r", mode, algo, password))
	time.Sleep(2 * time.Second)
	fmt.Fprintf(conn, "AT+WMODE=STA\r")
	time.Sleep(2 * time.Second)
	fmt.Fprintf(conn, "AT+Z\r")
	time.Sleep(2 * time.Second)

	return nil
}

func setColor(ip string, r int, g int, b int) error {
	conn := newConnection(ip, 5577)
	payload := []byte{0x31, byte(r), byte(g), byte(b), 0x00, 0x0F, 0x0F}
	err := conn.sendCommandNoReturn(payload)
	if err != nil {
		return err
	}
	return nil
}

func powerOn(ip string) error {
	conn := newConnection(ip, 5577)
	payload := []byte{0x71, 0x23, 0x0F}
	resp, err := conn.sendCommand(payload)
	if err != nil {
		return err
	}
	printHex(resp)
	return nil
}

func powerOff(ip string) error {
	conn := newConnection(ip, 5577)
	payload := []byte{0x71, 0x24, 0x0F}
	resp, err := conn.sendCommand(payload)
	if err != nil {
		return err
	}
	printHex(resp)
	return nil
}

func startHTTP(c *cli.Context) {

	handler := func(w http.ResponseWriter, r *http.Request) {
		pieces := strings.Split(r.URL.Path, "/")
		if len(pieces) < 3 {
			io.WriteString(w, "")
			return
		}

		ip := pieces[1]
		command := pieces[2]

		switch command {
		case "power-on":
			err := powerOn(ip)
			if err != nil {
				io.WriteString(w, err.Error())
				return
			}
			break
		case "power-off":
			err := powerOff(ip)
			if err != nil {
				io.WriteString(w, err.Error())
				return
			}
			break
		case "set-color":
			q := r.URL.Query()
			r, err := strconv.ParseInt(q.Get("r"), 16, 64)
			g, err := strconv.ParseInt(q.Get("g"), 16, 64)
			b, err := strconv.ParseInt(q.Get("b"), 16, 64)
			err = setColor(ip, int(r), int(g), int(b))
			if err != nil {
				io.WriteString(w, err.Error())
				return
			}
			break
		}

		io.WriteString(w, "OK")
	}

	http.HandleFunc("/", handler)
	log.Printf("Starting server on port %v", c.GetInt("port"))
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%v", c.GetInt("port")), nil))
}

func (c *connection) sendCommand(payload []byte) ([]byte, error) {
	localAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%v", c.localIPAddress, c.localPort))
	if err != nil {
		return nil, err
	}

	conn, err := net.DialTCP("tcp", localAddr, &net.TCPAddr{
		Port: c.remotePort,
		IP:   net.ParseIP(c.remoteIPAddress),
	})

	if err != nil {
		return nil, err
	}

	// checksum
	var acc byte = 0x0
	for _, x := range payload {
		acc += x
	}
	payload = append(payload, byte(acc&0xFF))

	// send payload
	_, err = conn.Write(payload)

	if err != nil {
		conn.Close()
		return nil, err
	}

	// receive response
	reply := make([]byte, 64)
	n, err := conn.Read(reply)
	reply = reply[:n]

	if err != nil {
		conn.Close()
		return nil, err
	}

	err = conn.Close()
	if err != nil {
		return nil, err
	}

	return reply, nil
}

func (c *connection) sendCommandNoReturn(payload []byte) error {
	localAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%v", c.localIPAddress, c.localPort))
	if err != nil {
		return err
	}

	conn, err := net.DialTCP("tcp", localAddr, &net.TCPAddr{
		Port: c.remotePort,
		IP:   net.ParseIP(c.remoteIPAddress),
	})

	if err != nil {
		return err
	}

	// checksum
	var acc byte = 0x0
	for _, x := range payload {
		acc += x
	}
	payload = append(payload, byte(acc&0xFF))

	// send payload
	_, err = conn.Write(payload)

	if err != nil {
		conn.Close()
		return err
	}

	err = conn.Close()
	return err
}

func printHex(arr []byte) {
	for _, h := range arr {
		fmt.Printf("%x ", h)
	}
}

func getLocalIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return ip.String(), nil
		}
	}
	return "", nil
}
