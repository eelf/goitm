package main

import (
	"log"
	"net"
	"strings"
	"os"
	"os/exec"
	"io"
	"crypto/tls"
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
)

func (r *WritableLogger) Write(p []byte) (n int, err error) {
	r.Println(string(p))
	return
}

func main() {
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
	logger := &WritableLogger{log.New(os.Stdout, c.RemoteAddr().String() + ": ", 0)}
	logger2 := &WritableLogger{log.New(os.Stdout, c.RemoteAddr().String() + ": ", 0)}
	logger.Println("CONNECTED")
	cmd := exec.Command("/sbin/pfctl", "-s", "state")
	out, err := cmd.Output()
	if err != nil {
		panic(err)
	}
	host, port := parsePfctl(string(out), c.RemoteAddr().String())

	logger.Println("hostport", host, port)

	u, err := net.Dial("tcp", host + ":" + port)
	if err != nil {
		panic(err)
	}

	if port != "443" {
		logger.SetPrefix(logger.Prefix() + "u->c\n\n")
		logger2.SetPrefix(logger2.Prefix() + "c->u\n\n")
		tu := io.TeeReader(u, logger)
		tc := io.TeeReader(c, logger2)

		go io.Copy(c, tu)
		io.Copy(u, tc)
		return
	}

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
