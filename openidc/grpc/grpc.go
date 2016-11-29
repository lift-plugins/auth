// +build !dev

package grpc

import (
	"net/url"
	"strings"

	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

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

	// We do not fail if there is any problem getting locally stored access token.
	// Since we want to let RPC calls, to public endpoints, go through just fine. Instead,
	// We allow the server to complain back if an endpoint requiring authentication is attempting
	// to be accessed without an access token.
	creds, err := RPCCredentials()
	if err == nil {
		clientOpts = append(clientOpts, grpc.WithPerRPCCredentials(creds))
	}

	return grpc.Dial(address, clientOpts...)
}
