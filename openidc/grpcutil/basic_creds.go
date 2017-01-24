package grpcutil

import (
	"encoding/base64"

	"golang.org/x/net/context"
	"google.golang.org/grpc/credentials"
)

type basicCreds struct {
	username, password string
}

// BasicCreds implements PerRPCCredentials for sending Basic authorization credentials.
// This is used when interacting with any of the token services as well as to dynamically register OpenIDC Clients.
func BasicCreds(username, password string) credentials.PerRPCCredentials {
	return &basicCreds{
		username: username,
		password: password,
	}
}

func (c *basicCreds) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	if c.username == "" {
		return nil, nil
	}
	return map[string]string{
		"authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(c.username+":"+c.password)),
	}, nil
}

func (c *basicCreds) RequireTransportSecurity() bool {
	return true
}
