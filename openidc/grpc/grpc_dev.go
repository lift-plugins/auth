// +build dev

package grpc

import (
	"crypto/x509"
	"log"
	"net/url"
	"strings"

	"github.com/pkg/errors"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const tlsCert = `
-----BEGIN CERTIFICATE-----
MIIDUzCCAtmgAwIBAgIJAKTf/aVGhWkYMAkGByqGSM49BAEwgZExCzAJBgNVBAYT
AlVTMREwDwYDVQQIEwhOZXcgWW9yazERMA8GA1UEBxMITmV3IFlvcmsxFzAVBgNV
BAoTDkhvb2tsaWZ0LCBJbmMuMRQwEgYDVQQLEwtFbmdpbmVlcmluZzEKMAgGA1UE
AxQBKjEhMB8GCSqGSIb3DQEJARYSY2FtaWxvQGhvb2tsaWZ0LmlvMCAXDTE2MTEx
NDE0NTgwNFoYDzIxMTUwNjA5MTQ1ODA0WjCBkTELMAkGA1UEBhMCVVMxETAPBgNV
BAgTCE5ldyBZb3JrMREwDwYDVQQHEwhOZXcgWW9yazEXMBUGA1UEChMOSG9va2xp
ZnQsIEluYy4xFDASBgNVBAsTC0VuZ2luZWVyaW5nMQowCAYDVQQDFAEqMSEwHwYJ
KoZIhvcNAQkBFhJjYW1pbG9AaG9va2xpZnQuaW8wdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAASH3bmfhqPNDE2YdeBG15Yl13GVWlex0QDCh85koZ3kbKMGdDBqgb5gqgwZ
F1rCCpjff+o3D3JaAMYosACOyHn8lnJOcpryqUkwCklxSQqleLJM4EGSitMm8119
tzYhaCajgfkwgfYwHQYDVR0OBBYEFMNqnVpZOU6jIqWaiHr7AnMXpBwWMIHGBgNV
HSMEgb4wgbuAFMNqnVpZOU6jIqWaiHr7AnMXpBwWoYGXpIGUMIGRMQswCQYDVQQG
EwJVUzERMA8GA1UECBMITmV3IFlvcmsxETAPBgNVBAcTCE5ldyBZb3JrMRcwFQYD
VQQKEw5Ib29rbGlmdCwgSW5jLjEUMBIGA1UECxMLRW5naW5lZXJpbmcxCjAIBgNV
BAMUASoxITAfBgkqhkiG9w0BCQEWEmNhbWlsb0Bob29rbGlmdC5pb4IJAKTf/aVG
hWkYMAwGA1UdEwQFMAMBAf8wCQYHKoZIzj0EAQNpADBmAjEAnvDrqcg7Sl2wK/bH
+98IMGMiYdT1FpSqCT3YyVQeCPELlxmnXbzNesY/R+l8oY9bAjEAhya4BL+ingli
o9FuJqdUS5o9Rgii55nFhNdzQvT/p/ANGHBCfQyUNtAjPp92KvXC
-----END CERTIFICATE-----
`

func Connection(address, userAgent string) (*grpc.ClientConn, error) {
	// go-grpc fails if address has a scheme
	if strings.HasPrefix(address, "http") {
		u, err := url.Parse(address)
		if err != nil {
			return nil, errors.Wrapf(err, "failed parsing provider address: %q", address)
		}
		address = u.Host
	}

	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM([]byte(tlsCert))
	if !ok {
		log.Fatal("Unable to append server TLS cert to cert pool")
	}

	clientCreds := credentials.NewClientTLSFromCert(certPool, address)
	clientOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(clientCreds),
		grpc.WithUserAgent(userAgent),
	}

	creds, err := RPCCredentials()
	if err == nil {
		clientOpts = append(clientOpts, grpc.WithPerRPCCredentials(creds))
	}

	return grpc.Dial(address, clientOpts...)
}
