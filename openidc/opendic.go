package openidc

import (
	"context"

	"github.com/pkg/errors"

	api "github.com/hooklift/apis/go/identity"
	"github.com/hooklift/lift/ui"
	"github.com/lift-plugins/auth/openidc/clients"
	"github.com/lift-plugins/auth/openidc/grpcutil"
)

// RegisterClient creates a lift CLI client for the account identified by username and password.
func RegisterClient(ctx context.Context, address, username, password string) (*clients.Client, error) {
	clientApp := new(clients.Client)
	var err error
	if err = clientApp.Read(); err == nil {
		return clientApp, nil
	}

	ui.Debug("Client not found: %+v", err)
	ui.Debug("Creating a new client...")

	grpcConn, err := grpcutil.Connection(address, "lift-auth", username, password)
	if err != nil {
		return nil, errors.Wrap(err, "failed connecting to openid provider.")
	}
	defer grpcConn.Close()

	clientService := api.NewAppsClient(grpcConn)
	req := &api.RegisterApp{
		ClientName:      "Lift CLI",
		ClientUri:       "https://www.hooklift.io/lift?user=" + username,
		ApplicationType: "native",
		RedirectUris:    []string{"http://localhost:9999/callback"},
		ResponseTypes:   []string{"token", "id_token"},
		GrantTypes:      []string{"password", "refresh_token"},
		LogoUri:         "https://avatars1.githubusercontent.com/u/22415297?v=3&s=200",
		Contacts:        []string{"eng@hooklift.io"},
		PolicyUri:       "https://www.hooklift.io/policy/privacy",
		TosUri:          "https://www.hooklift.io/policy/tos",
		IdTokenSignedResponseAlg: "ES256",
	}

	res, err := clientService.Register(ctx, req)
	if err != nil {
		return nil, errors.Wrapf(err, "failed registering openidc client for Lift")
	}

	clientApp.RegisterApp = *res
	if err := clientApp.Write(); err != nil {
		return nil, err
	}

	return clientApp, nil
}
