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

	creds, err := rpcCredentials(address)
	if err == nil {
		clientOpts = append(clientOpts, grpc.WithPerRPCCredentials(creds))
	}

	return grpc.Dial(address, clientOpts...)
}
