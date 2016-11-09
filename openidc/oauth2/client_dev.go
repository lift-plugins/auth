// +build dev

package oauth2

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
)

const tlsCert = `
-----BEGIN CERTIFICATE-----
MIIDUTCCAtegAwIBAgIJAOWuQSsLeG+zMAkGByqGSM49BAEwgZExCzAJBgNVBAYT
AlVTMREwDwYDVQQIEwhOZXcgWW9yazERMA8GA1UEBxMITmV3IFlvcmsxFzAVBgNV
BAoTDkhvb2tsaWZ0LCBJbmMuMRQwEgYDVQQLEwtFbmdpbmVlcmluZzEKMAgGA1UE
AxQBKjEhMB8GCSqGSIb3DQEJARYSY2FtaWxvQGhvb2tsaWZ0LmlvMB4XDTE2MDgx
NTIwMjQyNVoXDTE2MTExMzIwMjQyNVowgZExCzAJBgNVBAYTAlVTMREwDwYDVQQI
EwhOZXcgWW9yazERMA8GA1UEBxMITmV3IFlvcmsxFzAVBgNVBAoTDkhvb2tsaWZ0
LCBJbmMuMRQwEgYDVQQLEwtFbmdpbmVlcmluZzEKMAgGA1UEAxQBKjEhMB8GCSqG
SIb3DQEJARYSY2FtaWxvQGhvb2tsaWZ0LmlvMHYwEAYHKoZIzj0CAQYFK4EEACID
YgAELp07EO1MczG950aucWp3qxo5FVT+9BZL5iDJiE31FkbqGZuFf7gOwB7kmeGW
1x+Ws7KGPaPgYKDaUHseuJkS+3+hguw4BY6eBcCbU1YDKS0bIgU6F5p2tiXbSBpC
K1GSo4H5MIH2MB0GA1UdDgQWBBRfGlwOi5nklQEonzq66YnoWp+yTzCBxgYDVR0j
BIG+MIG7gBRfGlwOi5nklQEonzq66YnoWp+yT6GBl6SBlDCBkTELMAkGA1UEBhMC
VVMxETAPBgNVBAgTCE5ldyBZb3JrMREwDwYDVQQHEwhOZXcgWW9yazEXMBUGA1UE
ChMOSG9va2xpZnQsIEluYy4xFDASBgNVBAsTC0VuZ2luZWVyaW5nMQowCAYDVQQD
FAEqMSEwHwYJKoZIhvcNAQkBFhJjYW1pbG9AaG9va2xpZnQuaW+CCQDlrkErC3hv
szAMBgNVHRMEBTADAQH/MAkGByqGSM49BAEDaQAwZgIxALaiHMepDgC+s/YOppjh
2Nj7ZVhRsyZXXirdBRv9WPJNr63ZVLc/ZknPtUCowr9IvgIxAL61ltwoDHcGRUj2
YwpZ+1QyNNCekHodFohHj/jKwcHebgPrGABvs86bStKpT4ThuQ==
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
