package grpcutil

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"

	"github.com/hooklift/lift/ui"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// This gets defined with a self-signed certificate if "dev" build tag is used during
// compilation. See grpc_dev.go
var tlsCert = ""

// Connection returns a server connection to gRPC service on the provided address, handling token authentication and refreshing.
// If credentials are provided a Basic Authorization header is sent along.
func Connection(address, userAgent string, creds ...string) (*grpc.ClientConn, error) {
	// go-grpc fails if address has a scheme
	if !strings.HasPrefix(address, "http") {
		address = fmt.Sprintf("https://%s", address)
	}

	u, err := url.Parse(address)
	if err != nil {
		return nil, errors.Wrapf(err, "failed parsing provider address: %q", address)
	}

	address = u.Host // it includes the port ¯\_(ツ)_/¯
	clientOpts := []grpc.DialOption{
		grpc.WithUserAgent(userAgent),
	}

	// If tlsCert is not empty it means, this binary was compiled with "dev" build tag
	if tlsCert != "" {
		certPool := x509.NewCertPool()
		ok := certPool.AppendCertsFromPEM([]byte(tlsCert))
		if !ok {
			ui.Fatal("Unable to append server TLS cert to cert pool")
		}

		clientTLS := credentials.NewClientTLSFromCert(certPool, "")
		clientOpts = append(clientOpts, grpc.WithTransportCredentials(clientTLS))
	}

	// We do not fail if there is any problem getting locally stored access token.
	// Since we want to let RPC calls to public endpoints go through just fine. Instead,
	// we allow the server to complain back if an endpoint requiring authentication is
	// attempting to be accessed without an access token or openidc client credentials.
	tokenCreds, err := accessTokenCreds()
	if err == nil {
		clientOpts = append(clientOpts, grpc.WithPerRPCCredentials(tokenCreds))
	}

	if len(creds) >= 2 {
		basicCreds := BasicCreds(creds[0], creds[1])
		clientOpts = append(clientOpts, grpc.WithPerRPCCredentials(basicCreds))
	}

	return grpc.Dial(address, clientOpts...)
}
