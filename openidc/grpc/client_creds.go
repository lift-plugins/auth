package grpc

import (
	"encoding/base64"

	"golang.org/x/net/context"
	"google.golang.org/grpc/credentials"
)

type clientCreds struct {
	username, password string
}

// ClientCreds implements PerRPCCredentials for sending client credentials. This is
// used when interacting with any of the token services.
func ClientCreds(username, password string) credentials.PerRPCCredentials {
	if username == "" || password == "" {
		panic("client credentials must not be empty")
	}

	return &clientCreds{
		username: username,
		password: password,
	}
}

func (c *clientCreds) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(c.username+":"+c.password)),
	}, nil
}

func (c *clientCreds) RequireTransportSecurity() bool {
	return true
}
