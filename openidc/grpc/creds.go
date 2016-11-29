package grpc

import (
	"github.com/lift-plugins/auth/openidc/tokens"

	"golang.org/x/net/context"
	"google.golang.org/grpc/credentials"
)

type creds struct {
	tks *tokens.Tokens
}

// RPCCredentials returns an implementation of credentials.PerRPCCredentials. Used to
// authenticate GRPC calls against the server. If there are any errors, no authentication
// is sent to the gRPC server.
func RPCCredentials() (credentials.PerRPCCredentials, error) {
	tks := new(tokens.Tokens)
	if err := tks.Read(); err != nil {
		return nil, err
	}

	return &creds{
		tks: tks,
	}, nil
}

func (c *creds) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	if err := c.tks.RefreshIfExpired(); err != nil {
		return nil, err
	}

	return map[string]string{
		"authorization": "Bearer " + c.tks.Access,
	}, nil
}

func (c *creds) RequireTransportSecurity() bool {
	return true
}
