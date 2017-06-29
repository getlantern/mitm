// Package mitm provides a facility for man-in-the-middling pairs of
// connections.
package mitm

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/getlantern/go-cache/cache"
	"github.com/getlantern/keyman"
	"github.com/getlantern/reconn"
)

const (
	oneDay   = 24 * time.Hour
	twoWeeks = oneDay * 14
	oneMonth = 1
	oneYear  = 1
	tenYears = 10 * oneYear

	maxTLSRecordSize = 2 << 15
)

// Opts provides options to configure mitm
type Opts struct {
	// Organization: Name of the organization to use on the generated CA cert for this (defaults to "gomitm")
	Organization string

	// CommonName: CommonName to use on the generated CA cert for this proxy (defaults to "Lantern")
	CommonName string

	// InstallCerts: If true, the site-specific certs will be installed to the system's keystore
	InstallCerts bool

	// ServerTLSConfig: optional configuration for TLS server when MITMing (if nil, a sensible default is used)
	ServerTLSConfig *tls.Config

	// ClientTLSConfig: optional configuration for TLS client when MITMing (if nil, a sensible default is used)
	ClientTLSConfig *tls.Config
}

// Configure creates an MITM that can man-in-the-middle a pair of connections.
// The hostname is determined using SNI. If no SNI header is present, then the
// connection is not MITM'ed. The primary key and certificate used to generate
// and sign MITM certificates are auto-created if not already present.
func Configure(opts *Opts) (*Interceptor, error) {
	ic := &Interceptor{
		opts:         opts,
		dynamicCerts: cache.NewCache(),
	}
	err := ic.initCrypto()
	if err != nil {
		return nil, err
	}
	return ic, nil
}

// Interceptor provides a facility for MITM'ing pairs of connections.
type Interceptor struct {
	opts            *Opts
	pk              *keyman.PrivateKey
	pkPem           []byte
	serverTLSConfig *tls.Config
	clientTLSConfig *tls.Config
	dynamicCerts    *cache.Cache
	certMutex       sync.Mutex
}

// MITM man-in-the-middles a pair of connections, returning the connections that
// should be used in place of the originals. If the original connections can't
// be MITM'ed but can continue to be used as-is, those will be returned.
func (ic *Interceptor) MITM(downstream net.Conn, upstream net.Conn) (newDown net.Conn, newUp net.Conn, success bool, err error) {
	rc := reconn.Wrap(downstream, maxTLSRecordSize)
	adDown := &alertDetectingConn{Conn: rc}
	tlsDown := tls.Server(adDown, ic.serverTLSConfig)
	handshakeErr := tlsDown.Handshake()
	if handshakeErr == nil {
		tlsConfig := makeConfig(ic.clientTLSConfig)
		tlsConfig.ServerName = tlsDown.ConnectionState().ServerName
		tlsUp := tls.Client(upstream, tlsConfig)
		return tlsDown, tlsUp, true, tlsUp.Handshake()
	} else if adDown.sawAlert() {
		// Don't MITM, send any received handshake info on to upstream
		rr, err := rc.Rereader()
		if err != nil {
			return nil, nil, false, fmt.Errorf("Unable to re-attempt TLS connection to upstream: %v", err)
		}
		_, err = io.Copy(upstream, rr)
		if err != nil {
			return nil, nil, false, err
		}
		return rc, upstream, false, nil
	}
	return nil, nil, false, handshakeErr
}

func (ic *Interceptor) initCrypto() (err error) {
	if ic.opts.Organization == "" {
		ic.opts.Organization = "gomitm"
	}
	if ic.opts.CommonName == "" {
		ic.opts.CommonName = "Lantern"
	}
	ic.pk, err = keyman.GeneratePK(2048)
	if err != nil {
		return fmt.Errorf("Unable to generate private key: %s", err)
	}
	ic.pkPem = ic.pk.PEMEncoded()
	ic.serverTLSConfig = makeConfig(ic.opts.ServerTLSConfig)
	ic.serverTLSConfig.GetCertificate = ic.makeCertificate

	ic.clientTLSConfig = ic.opts.ClientTLSConfig
	return
}

func (ic *Interceptor) makeCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := clientHello.ServerName
	if name == "" {
		return nil, fmt.Errorf("No ServerName provided")
	}

	// Try to read an existing cert
	kpCandidateIf, found := ic.dynamicCerts.Get(name)
	if found {
		return kpCandidateIf.(*tls.Certificate), nil
	}

	// Existing cert not found, lock for writing and recheck
	ic.certMutex.Lock()
	defer ic.certMutex.Unlock()
	kpCandidateIf, found = ic.dynamicCerts.Get(name)
	if found {
		return kpCandidateIf.(*tls.Certificate), nil
	}

	// Still not found, create certificate
	certTTL := twoWeeks
	generatedCert, err := ic.pk.TLSCertificateFor(
		ic.opts.Organization,
		name,
		time.Now().Add(certTTL),
		false,
		nil)
	if err != nil {
		return nil, fmt.Errorf("Unable to issue certificate: %s", err)
	}
	if ic.opts.InstallCerts {
		err = generatedCert.InstallToUserKeyChain()
		if err != nil {
			return nil, fmt.Errorf("Unable to install cert to user keychain")
		}
	}
	keyPair, err := tls.X509KeyPair(generatedCert.PEMEncoded(), ic.pkPem)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse keypair for tls: %s", err)
	}

	// Add to cache, set to expire 1 day before the cert expires
	cacheTTL := certTTL - oneDay
	ic.dynamicCerts.Set(name, &keyPair, cacheTTL)
	return &keyPair, nil
}

// makeConfig makes a copy of a tls config if provided. Otherwise returns an
// empty tls config.
func makeConfig(template *tls.Config) *tls.Config {
	tlsConfig := &tls.Config{}
	if template != nil {
		// Copy the provided tlsConfig
		*tlsConfig = *template
	}
	return tlsConfig
}
