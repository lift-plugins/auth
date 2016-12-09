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

	serverConn, err := grpc.Connection(address, "lift-auth")
	if err != nil {
		// We were unable to revoke tokens in the server, so we just return
		// and let them expire.
		ui.Debug("%+v", errors.Wrap(err, "we were unable to revoke tokens in the server"))
		return nil
	}
	defer serverConn.Close()

	client := api.NewAuthzClient(serverConn)
	ctx := context.Background()

	if _, err := client.SignOut(ctx, new(api.SignOutRequest)); err != nil {
		ui.Debug("%+v", errors.Wrap(err, "failed signing user out from identity server"))
	}
	return nil
}
