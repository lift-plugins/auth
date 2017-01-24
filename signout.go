package auth

import (
	"context"

	api "github.com/hooklift/apis/go/identity"
	"github.com/hooklift/lift/ui"
	"github.com/lift-plugins/auth/openidc/clients"
	"github.com/lift-plugins/auth/openidc/grpcutil"
	"github.com/lift-plugins/auth/openidc/tokens"
	"github.com/pkg/errors"
)

// SignOut removes locally stored tokens and does best effort to revoke tokens from
// the OpenID Provider. Any error attempting to sign out from the identity server is silently ignored but
// can be seen if running plugin with DEBUG enabled.
func SignOut() error {
	defer tokens.Delete()

	tks := new(tokens.Tokens)
	if err := tks.Read(); err != nil {
		ui.Debug("%+v", errors.Wrap(err, "we were unable to revoke tokens in the server"))
		return nil
	}

	client := new(clients.Client)
	if err := client.Read(); err != nil {
		ui.Debug("%+v", err)
		return nil
	}

	serverConn, err := grpcutil.Connection(tks.Issuer, "lift-auth", client.ClientId, client.ClientSecret)
	if err != nil {
		// We were unable to revoke tokens in the server, so we just return
		// and let them expire.
		ui.Debug("%+v", errors.Wrap(err, "we were unable to revoke tokens in the server"))
		return nil
	}
	defer serverConn.Close()

	authzClient := api.NewAuthzClient(serverConn)
	ctx := context.Background()

	if _, err := authzClient.SignOut(ctx, &api.SignOutRequest{
		IdToken: tks.ID,
	}); err != nil {
		ui.Debug("%+v", errors.Wrap(err, "failed signing user out from identity server"))
	}
	return nil
}
