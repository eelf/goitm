package main

import (
	"log"
	"net"
	"strings"
	"os"
	"os/exec"
	"io"
	"crypto/tls"
	"time"
	"golang.org/x/net/proxy"
	"bufio"
)

/*
pf:
rdr on en0 proto tcp from 192.168.1.37 to any -> 127.0.0.1 port 12345
nat on en0 proto udp from 192.168.1.37 to any -> (en0)


pfctl -d && pfctl -F all && pfctl -f pf && pfctl -e
pfctl -s all

*/

type WritableLogger struct {
	*log.Logger
}

var (
	oidExtensionSubjectAltName        = []int{2, 5, 29, 17}
	hostproxy map[string]bool
)

func (r *WritableLogger) Write(p []byte) (n int, err error) {
	r.Println(string(p))
	return
}

func main() {
	hostproxy = make(map[string]bool)

	file, err := os.Open("hostsproxy")
	if err != nil {
		b := bufio.NewReader(file)
		for {
			line, _, err := b.ReadLine()
			if err != nil {
				break
			}
			hostproxy[string(line)] = true
		}
	} else {
		log.Println("could not open hostsproxy file", err)
	}
	s, err := net.Listen("tcp", "0:12345")
	if err != nil {
		panic(err)
	}
	for {
		c, err := s.Accept()
		if err != nil {
			panic(err)
		}
		go client(c)
	}
}

func parsePfctl(out, addr string) (string, string) {
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Index(line, addr) != -1 &&
			strings.Index(line, "ESTABLISHED:ESTABLISHED") != -1 {
			parts := strings.Split(line, " ")
			if len(parts) >= 5 {
				host, port, err := net.SplitHostPort(parts[4])
				if err == nil {
					return host, port
				}
			}
		}
	}
	return "", ""
}

func client(c net.Conn) {
	defer c.Close()
	logger := &WritableLogger{log.New(os.Stdout, c.RemoteAddr().String() + ": ", 0)}
	logger.Println("CONNECTED")
	cmd := exec.Command("/sbin/pfctl", "-s", "state")
	out, err := cmd.Output()
	if err != nil {
		panic(err)
	}
	host, port := parsePfctl(string(out), c.RemoteAddr().String())
	logger.Println("hostport", host, port)

	u := connectToRemote(logger, host, port)
	if u == nil {
		return
	}

	doMitm := port == "443"
	doMitm = false
	if !doMitm {
		proxyConn(u, c, port != "443", logger)
	} else {
		proxyCryptoConn(u, c, logger)
	}
}

func connectToRemote(logger *WritableLogger, host, port string) (u net.Conn) {
	var err error
	if hostproxy[host] {
		d, err := proxy.SOCKS5("tcp", "127.0.0.1:9150", nil, proxy.Direct)
		if err != nil {
			logger.Println("could not use socks5", err)
			return nil
		}
		u, err = d.Dial("tcp", host + ":" + port)
		if err != nil {
			logger.Println("could not dial using socks5", host + ":" + port, err)
			return nil
		}
	} else {
		u, err = net.DialTimeout("tcp", host + ":" + port, 10 * time.Second)
		if err != nil {
			logger.Println("could not dial", host + ":" + port, err)
			return nil
		}
	}
	return u
}

func proxyConn(u, c net.Conn, withLog bool, logger *WritableLogger) {
	var tu, tc io.Reader
	if withLog {
		logger2 := &WritableLogger{log.New(os.Stdout, c.RemoteAddr().String() + ": ", 0)}

		logger.SetPrefix(logger.Prefix() + "u->c\n\n")
		logger2.SetPrefix(logger2.Prefix() + "c->u\n\n")
		tu = io.TeeReader(u, logger)
		tc = io.TeeReader(c, logger2)
	} else {
		tu = u
		tc = c
	}

	go io.Copy(c, tu)
	io.Copy(u, tc)
}

func proxyCryptoConn(u, c net.Conn, logger *WritableLogger) {
	var err error
	config := &tls.Config{
		InsecureSkipVerify: true,
	}
	client := tls.Client(u, config)

	err = client.Handshake()
	if err != nil {
		logger.Println("client hs err", err)
		return
	}
	state := client.ConnectionState()
	for _, cert := range state.PeerCertificates {
		hasSanExtension := false
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(oidExtensionSubjectAltName) {
				hasSanExtension = true
			}
		}
		logger.Println("upstream cert ip", cert.IPAddresses,
			"has san ext", hasSanExtension,
			"dns", cert.DNSNames,
			"subj.commn", cert.Subject.CommonName)
	}

	server := tls.Server(c, config)

	go func() {
		buf := make([]byte, 8192)
		for {
			n, err := server.Read(buf)
			if err != nil {
				logger.Println("server to client read err", err)
				return
			}
			buf = buf[0:n]
			logger.Println(string(buf))
			n, err = client.Write(buf)
			if err != nil {
				logger.Println("server to client write err", err)
				return
			}
			buf = buf[:]
		}
	}()

	buf := make([]byte, 8192)
	for {
		n, err := client.Read(buf)
		if err != nil {
			logger.Println("client to server read err", err)
			return
		}
		buf = buf[0:n]
		logger.Println(string(buf))
		n, err = server.Write(buf)
		if err != nil {
			logger.Println("client to server write err", err)
			return
		}
		buf = buf[:]
	}
}