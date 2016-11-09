package auth

import (
	"context"
	"crypto/rand"
	"fmt"

	api "github.com/hooklift/apis/go/identity"
	"github.com/hooklift/lift"
	"github.com/lift-plugins/auth/openidc/discovery"
	"github.com/lift-plugins/auth/openidc/grpc"
	"github.com/lift-plugins/auth/openidc/tokens"

	"github.com/pkg/errors"
)

// SignIn authenticates the user against an identity provider.
func SignIn(email, password, address string) error {
	csrfToken, err := randomValue()
	if err != nil {
		return errors.Wrap(err, "failed generating cryptographic random value for CSRF token")
	}

	nonce, err := randomValue()
	if err != nil {
		return errors.Wrap(err, "failed generating cryptographic random value for ID Token nonce")
	}

	req := &api.SignInRequest{
		Username:     email,
		Password:     string(password),
		Scope:        "openid name email offline_access",
		ResponseType: "token id_token",
		ClientId:     lift.ClientID,
		State:        csrfToken,
		Nonce:        nonce,
	}

	serverConn, err := grpc.Connection(address, "lift-auth")
	if err != nil {
		return errors.Wrap(err, "failed connecting to openid provider")
	}
	defer serverConn.Close()

	client := api.NewAuthzClient(serverConn)
	ctx := context.Background()

	resp, err := client.SignIn(ctx, req)
	if err != nil {
		return errors.Wrap(err, "failed signing user in")
	}

	if resp.State != csrfToken {
		return errors.New("csrf token received does not match the value we sent")
	}

	// Discovers OpenID Connect configuration for the given provider address and refreshes cached
	// configuration and signing keys.
	if err := discovery.Run(address); err != nil {
		return errors.Wrapf(err, "failed discovering provider configuration from %q", address)
	}

	tokens := &tokens.Tokens{
		Issuer:  address,
		ID:      resp.IdToken,
		Access:  resp.AccessToken,
		Refresh: resp.RefreshToken,
	}

	// Validates ID token signature, downloading provider config and signing keys if necessary.
	if err := tokens.Validate(nonce); err != nil {
		return errors.Wrap(err, "failed validating tokens received from provider")
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
