package auth

import "github.com/hooklift/lift/openidc/tokens"

// Tokens returns the ID Token and Access token for the current user session.
func Tokens() (string, string, error) {
	tks := new(tokens.Tokens)
	if err := tks.Read(); err != nil {
		return "", "", err
	}

	return tks.ID, tks.Access, nil
}
