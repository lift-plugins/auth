package clients

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"google.golang.org/grpc"

	api "github.com/hooklift/apis/go/identity"
	"github.com/hooklift/lift/config"
)

var clientPath = filepath.Join(config.WorkDir, "client.json")

// Register creates a lift CLI client for the current logged user.
func Register(ctx context.Context, serverConn *grpc.ClientConn) error {
	client := new(Client)
	if err := client.Read(); err == nil {
		return nil
	}

	grpcClient := api.NewAppsClient(serverConn)
	req := &api.RegisterApp{
		ClientName:      "Lift CLI",
		ClientUri:       "https://www.hooklift.io/lift",
		ApplicationType: "native",
		RedirectUris:    []string{"http://localhost/lift/callback"},
		ResponseTypes:   []string{"token", "id_token"},
		GrantTypes:      []string{"password", "refresh_token"},
		LogoUri:         "https://avatars1.githubusercontent.com/u/22415297?v=3&s=200",
		Contacts:        []string{"id@hooklift.io"},
		PolicyUri:       "https://www.hooklift.io/policy/privacy",
		TosUri:          "https://www.hooklift.io/policy/tos",
		IdTokenSignedResponseAlg: "ES256",
	}

	res, err := grpcClient.Register(ctx, req)
	if err != nil {
		return errors.Wrapf(err, "failed registering openidc client")
	}

	clientApp := new(Client)
	clientApp.RegisterApp = *res

	return clientApp.Write()
}

// Client represents the OpenID Connect application used by Lift.
type Client struct {
	api.RegisterApp
}

// Write persist client data to disk.
func (c *Client) Write() error {
	data, err := json.MarshalIndent(c, "", "\t")
	if err != nil {
		return errors.Wrap(err, "failed marshaling client data")
	}

	if err := ioutil.WriteFile(clientPath, data, os.FileMode(0600)); err != nil {
		return errors.Wrapf(err, "failed writing client data to %q", clientPath)
	}
	return nil
}

// Read loads up client data from disk.
func (c *Client) Read() error {
	data, err := ioutil.ReadFile(clientPath)
	if err != nil {
		return errors.Wrapf(err, "failed reading tokens file at %q", clientPath)
	}

	if err := json.Unmarshal(data, &c); err != nil {
		return errors.Wrapf(err, "failed unmarshaling tokens file at %q", clientPath)
	}
	return nil
}
