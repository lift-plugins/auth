package grpc

import (
	"golang.org/x/net/context"
	"google.golang.org/grpc/credentials"

	"github.com/lift-plugins/auth/openidc/tokens"
)

type tokenCreds struct {
	tks *tokens.Tokens
}

// AccessTokenCreds returns an implementation of credentials.PerRPCCredentials. Used to
// authenticate GRPC calls against the server. If there are any errors, no authentication
// is sent to the gRPC server.
func AccessTokenCreds() (credentials.PerRPCCredentials, error) {
	tks := new(tokens.Tokens)
	if err := tks.Read(); err != nil {
		return nil, err
	}

	return &tokenCreds{
		tks: tks,
	}, nil
}

func (c *tokenCreds) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	if err := c.tks.RefreshIfExpired(); err != nil {
		return nil, err
	}

	return map[string]string{
		"authorization": "Bearer " + c.tks.Access,
	}, nil
}

func (c *tokenCreds) RequireTransportSecurity() bool {
	return true
}
