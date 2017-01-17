package auth

import (
	"crypto/rand"
	"fmt"

	"github.com/pkg/errors"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	api "github.com/hooklift/apis/go/identity"
	"github.com/hooklift/lift/ui"
	"github.com/lift-plugins/auth/openidc/clients"
	"github.com/lift-plugins/auth/openidc/discovery"
	apigrpc "github.com/lift-plugins/auth/openidc/grpc"
	"github.com/lift-plugins/auth/openidc/tokens"
)

// SignIn authenticates the user against an identity provider.
func SignIn(email, password, address string) error {
	ctx := context.Background()

	grpcConn, err := apigrpc.Connection(address, "lift-auth", email, password)
	if err != nil {
		return errors.Wrap(err, "failed connecting to openid provider.")
	}
	defer grpcConn.Close()

	client, err := clients.Register(ctx, grpcConn, email)
	if err != nil {
		return err
	}

	csrfToken, err := randomValue()
	if err != nil {
		return errors.Wrap(err, "failed getting random value for CSRF token")
	}

	nonce, err := randomValue()
	if err != nil {
		return errors.Wrap(err, "failed getting random value for ID Token nonce")
	}

	req := &api.SignInRequest{
		Username:     email,
		Password:     password,
		Scope:        []string{"openid", "name", "email", "offline_access", "admin"},
		ResponseType: []string{"token", "id_token"},
		Audience: []string{
			// To be able to publish and unpublish Lift plugins from Lift registry.
			"https://lift.hooklift.io",
			// To be able to interact with Hooklift's Platform API to deploy apps,
			// tail logs, manage apps configurations, etc.
			"https://api.hooklift.io",
			// To be able to interactively deploy using Lift CLI
			"https://git.hooklift.io",
		},
		State: csrfToken,
		Nonce: nonce,
	}

	authz := api.NewAuthzClient(grpcConn)
	resp, err := authz.SignIn(ctx, req)
	if err != nil {
		gcode := grpc.Code(err)
		if gcode == codes.Unauthenticated || gcode == codes.NotFound {
			return errors.New("Email or password is not valid")
		}

		ui.Debug("%+v", errors.Wrap(err, "failed signing user in"))
		return errors.New("We failed signing you in. Please try again.")
	}

	if resp.State != csrfToken {
		return errors.New("CSRF token received does not match value sent.")
	}

	// Discovers OpenID Connect configuration for the given provider address and refreshes cached
	// configuration and signing keys.
	if err := discovery.Run(address); err != nil {
		return errors.Wrapf(err, "failed discovering identity config from %q", address)
	}

	tokens := &tokens.Tokens{
		Issuer:  address,
		ID:      resp.IdToken,
		Access:  resp.AccessToken,
		Refresh: resp.RefreshToken,
	}

	// Verifies that ID token hasn't been tampared by checking its signature and relationship
	// with the Access token.
	if err := tokens.Verify(client.ClientId, nonce); err != nil {
		return errors.Wrap(err, "failed validating received tokens")
	}

	return tokens.Write()
}

// randomValue returns a cryptographically random value.
func randomValue() (string, error) {
	b := make([]byte, 10)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", b), nil
}
