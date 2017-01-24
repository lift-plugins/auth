package grpcutil

import (
	"golang.org/x/net/context"
	"google.golang.org/grpc/credentials"

	"github.com/lift-plugins/auth/openidc/clients"
	"github.com/lift-plugins/auth/openidc/tokens"
)

type tokenCreds struct {
	tks          *tokens.Tokens
	clientID     string
	clientSecret string
}

// accessTokenCreds returns an implementation of credentials.PerRPCCredentials. Used to
// authenticate GRPC calls against the server. If there are any errors, no authentication
// is sent to the gRPC server.
func accessTokenCreds() (credentials.PerRPCCredentials, error) {
	tks := new(tokens.Tokens)
	if err := tks.Read(); err != nil {
		return nil, err
	}

	client := new(clients.Client)
	if err := client.Read(); err != nil {
		return nil, err
	}

	return &tokenCreds{
		tks:          tks,
		clientID:     client.ClientId,
		clientSecret: client.ClientSecret,
	}, nil
}

func (c *tokenCreds) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	if err := c.tks.RefreshToken(c.clientID, c.clientSecret); err != nil {
		return nil, err
	}

	return map[string]string{
		"authorization": "Bearer " + c.tks.Access,
	}, nil
}

func (c *tokenCreds) RequireTransportSecurity() bool {
	return true
}
