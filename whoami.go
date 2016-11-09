package auth

import (
	"github.com/lift-plugins/auth/openidc/tokens"
)

// WhoAmI returns the email of the current logged user.
func WhoAmI() (string, error) {
	tks := new(tokens.Tokens)
	if err := tks.Read(); err != nil {
		return "", err
	}

	token, err := tokens.Decode(tks.ID)
	if err != nil {
		return "", err
	}

	return token.Email, nil
}
