// +build dev

package oauth2

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
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

// Injects self-sign TLS certificate to aid development.
func init() {
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(tlsCert))
	if !ok {
		panic("failed to parse root certificate")
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots},
	}

	Client.Transport = transport
}
