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

// This gets defined with a self-signed certificate if "dev" build tag is used during
// compilation. See grpc_dev.go
var tlsCert = ""

// Connection returns a server connection to the OpenIDConnect Provider.
func Connection(address, userAgent string) (*grpc.ClientConn, error) {
	// go-grpc fails if address has a scheme
	if strings.HasPrefix(address, "http") {
		u, err := url.Parse(address)
		if err != nil {
			return nil, errors.Wrapf(err, "failed parsing provider address: %q", address)
		}

		address = u.Host // it includes the port ¯\_(ツ)_/¯
	}

	clientOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")),
		grpc.WithUserAgent(userAgent),
	}

	if tlsCert != "" {
		certPool := x509.NewCertPool()
		ok := certPool.AppendCertsFromPEM([]byte(tlsCert))
		if !ok {
			log.Fatal("Unable to append server TLS cert to cert pool")
		}

		clientCreds := credentials.NewClientTLSFromCert(certPool, address)
		clientOpts = append(clientOpts, grpc.WithTransportCredentials(clientCreds))
	}

	// We do not fail if there is any problem getting locally stored access token.
	// Since we want to let RPC calls to public endpoints go through just fine. Instead,
	// we allow the server to complain back if an endpoint requiring authentication is
	// attempting to be accessed without an access token or openidc client credentials.
	tokenCreds, err := AccessTokenCreds()
	if err == nil {
		clientOpts = append(clientOpts, grpc.WithPerRPCCredentials(tokenCreds))
	}

	clientCreds := ClientCreds("7f60abff-de28-477b-9d5f-b546db04f7de", "6VTMEWsi,aM.9XscBrkLgBXEF*iDQ=8RBTbozpwyEywNyBj8@u")
	clientOpts = append(clientOpts, grpc.WithPerRPCCredentials(clientCreds))

	return grpc.Dial(address, clientOpts...)
}
