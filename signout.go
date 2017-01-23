package auth

import (
	"context"

	api "github.com/hooklift/apis/go/identity"
	"github.com/hooklift/lift/ui"
	"github.com/lift-plugins/auth/openidc/grpc"
	"github.com/lift-plugins/auth/openidc/tokens"
	"github.com/pkg/errors"
)

// SignOut removes locally stored tokens and does best effort to revoke tokens from
// the OpenID Provider.
func SignOut(address string) error {
	defer tokens.Delete()

	tks := new(tokens.Tokens)
	if err := tks.Read(); err != nil {
		ui.Debug("%+v", errors.Wrap(err, "we were unable to revoke tokens in the server"))
		return nil
	}

	serverConn, err := grpc.Connection(tks.Issuer, "lift-auth")
	if err != nil {
		// We were unable to revoke tokens in the server, so we just return
		// and let them expire.
		ui.Debug("%+v", errors.Wrap(err, "we were unable to revoke tokens in the server"))
		return nil
	}
	defer serverConn.Close()

	client := api.NewAuthzClient(serverConn)
	ctx := context.Background()

	if _, err := client.SignOut(ctx, &api.SignOutRequest{
		ClientId:     "",
		ClientSecret: "",
		IdToken:      tks.ID,
	}); err != nil {
		ui.Debug("%+v", errors.Wrap(err, "failed signing user out from identity server"))
	}
	return nil
}
