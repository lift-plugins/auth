package grpc

import (
	"crypto/x509"
	"net/url"
	"strings"

	"github.com/hooklift/lift/ui"
	"github.com/lift-plugins/auth/openidc/clients"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// This gets defined with a self-signed certificate if "dev" build tag is used during
// compilation. See grpc_dev.go
var tlsCert = ""

// Connection returns a server connection to the OpenIDConnect Provider.
func Connection(address, userAgent string, creds ...string) (*grpc.ClientConn, error) {
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

	// If tlsCert is not empty it means, this binary was compiled with "dev" build tag
	if tlsCert != "" {
		certPool := x509.NewCertPool()
		ok := certPool.AppendCertsFromPEM([]byte(tlsCert))
		if !ok {
			ui.Fatal("Unable to append server TLS cert to cert pool")
		}

		clientTLS := credentials.NewClientTLSFromCert(certPool, address)
		clientOpts = append(clientOpts, grpc.WithTransportCredentials(clientTLS))
	}

	// We do not fail if there is any problem getting locally stored access token.
	// Since we want to let RPC calls to public endpoints go through just fine. Instead,
	// we allow the server to complain back if an endpoint requiring authentication is
	// attempting to be accessed without an access token or openidc client credentials.
	tokenCreds, err := AccessTokenCreds()
	if err == nil {
		clientOpts = append(clientOpts, grpc.WithPerRPCCredentials(tokenCreds))
	}

	client := new(clients.Client)
	var basicCreds credentials.PerRPCCredentials
	if err := client.Read(); err != nil {
		// Most likely the client for the current user's CLI does not exist in her account
		// or the metadata was not found in her machine. So, we proceed to create or retrieve the client using
		// her account credentials as this is executed before attempting a sign-in.
		if len(creds) == 2 {
			basicCreds = BasicCreds(creds[0], creds[1])
		}
	} else {
		// We need to use client credentials when calling the sign-in service in the server as per the OpenID Connect spec.
		basicCreds = BasicCreds(client.ClientId, client.ClientSecret)
	}

	clientOpts = append(clientOpts, grpc.WithPerRPCCredentials(basicCreds))

	return grpc.Dial(address, clientOpts...)
}
