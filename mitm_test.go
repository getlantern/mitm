package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/getlantern/keyman"
	"github.com/getlantern/netx"
	"github.com/getlantern/tlsdefaults"
	"github.com/stretchr/testify/assert"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

const (
	text = "hello world"
)

// Make sure our pointer copying technique actually works.
func TestMakeTLS(t *testing.T) {
	template := &tls.Config{ServerName: "test"}
	made := makeConfig(template)
	if made.ServerName != template.ServerName {
		t.Error("Config not a copy")
	}
	template.ServerName = "different"
	if made.ServerName == template.ServerName {
		t.Error("Copy not a copy")
	}
}

// Make sure we can MITM a TLS connection with an SNI header.
func TestMITMSuccess(t *testing.T) {
	doTest(t, true, true, func(proxyAddr string, serverCert *x509.CertPool, proxyCert *x509.CertPool) (net.Conn, error) {
		return tls.Dial("tcp", proxyAddr, &tls.Config{
			ServerName: "localhost",
			RootCAs:    proxyCert,
		})
	})
}

// Make sure that we don't MITM a TLS connection without an SNI header.
func TestMITMNoSNI(t *testing.T) {
	doTest(t, true, false, func(proxyAddr string, serverCert *x509.CertPool, proxyCert *x509.CertPool) (net.Conn, error) {
		return tls.Dial("tcp", proxyAddr, &tls.Config{
			InsecureSkipVerify: true,
		})
	})
}

// Make sure that we don't MITM a plain-text connection.
func TestMITMNoTLS(t *testing.T) {
	doTest(t, false, false, func(proxyAddr string, serverCert *x509.CertPool, proxyCert *x509.CertPool) (net.Conn, error) {
		// Dial proxy
		return net.Dial("tcp", proxyAddr)
	})
}

func doTest(t *testing.T, listenTLS bool, expectSuccess bool, dial func(proxyAddr string, serverCert *x509.CertPool, proxyCert *x509.CertPool) (net.Conn, error)) {
	// make sure to clean up the temporary PEM files
	defer func() {
		files, _ := filepath.Glob("*.pem*")
		for _, f := range files {
			os.Remove(f)
		}
	}()
	// Echo server
	var l net.Listener
	var err error
	if listenTLS {
		l, err = tlsdefaults.Listen("localhost:0", "serverpk.pem", "servercert.pem")
	} else {
		l, err = net.Listen("tcp", "localhost:0")
	}
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	serverCert, err := keyman.LoadCertificateFromFile("servercert.pem")
	if !assert.NoError(t, err) {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		conn, acceptErr := l.Accept()
		if !assert.NoError(t, acceptErr) {
			return
		}
		io.Copy(conn, conn)
	}()

	// Interceptor
	opts := &Opts{
		PKFile:   "proxypk.pem",
		CertFile: "proxycert.pem",
		ClientTLSConfig: &tls.Config{
			RootCAs: serverCert.PoolContainingCert(),
		},
		Domains: []string{"localhost"},
	}

	ic, err := Configure(opts)
	if !assert.NoError(t, err) {
		return
	}

	// Proxy server
	pl, err := net.Listen("tcp", "localhost:0")
	if !assert.NoError(t, err) {
		return
	}
	defer pl.Close()

	proxyCert, err := keyman.LoadCertificateFromFile(ic.issuingCertFile)
	if !assert.NoError(t, err) {
		return
	}

	go func() {
		defer wg.Done()

		down, acceptErr := pl.Accept()
		if !assert.NoError(t, acceptErr) {
			return
		}
		up, err := net.Dial("tcp", l.Addr().String())
		if !assert.NoError(t, err) {
			return
		}
		newDown, newUp, success, err := ic.MITM(down, up)
		if !assert.NoError(t, err) {
			fmt.Println(err)
			return
		}
		if expectSuccess {
			assert.True(t, success, "Should be mitming successfully")
		}
		netx.BidiCopy(newUp, newDown, make([]byte, 32768), make([]byte, 32768))
		newDown.Close()
		newUp.Close()
	}()

	conn, err := dial(pl.Addr().String(), serverCert.PoolContainingCert(), proxyCert.PoolContainingCert())
	if !assert.NoError(t, err) {
		return
	}
	defer conn.Close()

	_, err = conn.Write([]byte(text))
	if !assert.NoError(t, err) {
		return
	}

	b := make([]byte, len(text))
	_, err = io.ReadFull(conn, b)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, text, string(b))
	conn.Close()

	wg.Wait()
}
