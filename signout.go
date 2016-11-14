package auth

import (
	"context"
	"log"

	api "github.com/hooklift/apis/go/identity"
	"github.com/lift-plugins/auth/openidc/grpc"
	"github.com/lift-plugins/auth/openidc/tokens"
)

// SignOut removes locally stored tokens and does best effort to revoke tokens from
// the OpenID Provider.
func SignOut(address string) error {
	defer func() {
		if err := tokens.Delete(); err != nil {
			log.Printf("%+v", err)
		}
	}()

	serverConn, err := grpc.Connection(address, "lift-auth")
	if err != nil {
		// We cannot do explicit revokation so we just return, leaving the identity
		// server to expire the tokens.
		return nil
	}
	defer serverConn.Close()

	client := api.NewAuthzClient(serverConn)
	ctx := context.Background()

	client.SignOut(ctx, new(api.SignOutRequest))
	return nil
}
