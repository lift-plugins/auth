package tokens

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	jose "gopkg.in/square/go-jose.v2"

	"github.com/hooklift/lift/config"
	"github.com/lift-plugins/auth/openidc/discovery"
	"github.com/lift-plugins/auth/openidc/oauth2"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

var (
	tokensPath = filepath.Join(config.WorkDir, "tokens.json")
)

// Tokens represents the tokens retrieved from the OpenID provider server.
type Tokens struct {
	Issuer  string `json:"issuer,omitempty"`
	ID      string `json:"id,omitempty"`
	Access  string `json:"access,omitempty"`
	Refresh string `json:"refresh,omitempty"`
}

// Read loads tokens from disk.
func (tks *Tokens) Read() error {
	data, err := ioutil.ReadFile(tokensPath)
	if err != nil {
		return errors.Wrapf(err, "failed reading tokens file at %q", tokensPath)
	}

	if err := json.Unmarshal(data, &tks); err != nil {
		return errors.Wrapf(err, "failed unmarshaling tokens file at %q", tokensPath)
	}
	return nil
}

// Write stores tokens to disk.
func (tks *Tokens) Write() error {
	data, err := json.MarshalIndent(tks, "", "\t")
	if err != nil {
		return errors.Wrap(err, "failed marshaling tokens")
	}

	if err := ioutil.WriteFile(tokensPath, data, os.FileMode(0600)); err != nil {
		return errors.Wrapf(err, "failed writing tokens to %q", tokensPath)
	}
	return nil
}

// Verify validates ID and Access tokens, according to:
// http://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.3.7
// http://openid.net/specs/openid-connect-core-1_0.html#ImplicitTokenValidation
func (tks *Tokens) Verify(clientID, nonce string) error {
	header, err := Verify(tks.ID)
	if err != nil {
		return err
	}

	idToken, err := Decode(tks.ID)
	if err != nil {
		return err
	}

	if idToken.Nonce != nonce {
		return errors.New("ID token nonce does not match nonce value sent in request")
	}

	if idToken.Issuer != tks.Issuer {
		return fmt.Errorf("issuer in ID token does not match the identity provider originally used: %s != %s", idToken.Issuer, tks.Issuer)
	}

	if idToken.AuthorizedParty != "" && idToken.AuthorizedParty != clientID {
		return errors.New("authorized party in ID token does not match client ID")
	}

	if idToken.Expired() {
		return errors.New("ID token has expired")
	}

	if tks.Access != "" && idToken.AtHash != "" {
		atHash := hash(tks.Access, header.Algorithm)
		if atHash != idToken.AtHash {
			return errors.New("calculated hash value from access token doesn't match value declared in ID token")
		}
	}

	return nil
}

// RefreshTokenResponse holds the response from the OpenIDC Provider when refreshing access tokens.
type refreshTokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
	IDToken          string `json:"id_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri"`
}

// RefreshToken refreshes ID, Access and Refresh tokens using current refresh token. Only if any of the tokens expired.
func (tks *Tokens) RefreshToken(clientID, clientSecret string) error {
	if tks.Access == "" {
		return errors.New("there is no access token to refresh")
	}

	if tks.Refresh == "" {
		return errors.New("no refresh token found")
	}

	accessToken, err := Decode(tks.Access)
	if err != nil {
		return err
	}

	idToken, err := Decode(tks.ID)
	if err != nil {
		return err
	}

	if !accessToken.Expired() && !idToken.Expired() {
		return nil
	}

	config := new(discovery.ProviderConfig)
	if err := config.Read(); err != nil {
		return err
	}

	nonce := uuid.NewV4().String()
	formValues := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tks.Refresh},
		"scope":         {strings.Join(accessToken.Scope, " ")},
		"state":         {nonce},
	}

	req, err := http.NewRequest(http.MethodPost, config.TokenEndpoint, strings.NewReader(formValues.Encode()))
	if err != nil {
		return errors.Wrapf(err, "failed preparing HTTP request")
	}

	req.SetBasicAuth(clientID, clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := oauth2.Client.Do(req)
	if err != nil {
		return errors.Wrapf(err, "failed refreshing access token")
	}
	defer resp.Body.Close()

	refreshRes := new(refreshTokenResponse)
	body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1<<20)) // reads up to 1mb
	if err != nil {
		return errors.Wrapf(err, "failed reading response body")
	}

	if err := json.Unmarshal(body, refreshRes); err != nil {
		return errors.Wrapf(err, "failed unmarshaling response: %s", string(body[:]))
	}

	if refreshRes.Error != "" {
		return fmt.Errorf("%s: %s. %s", refreshRes.Error, refreshRes.ErrorDescription, refreshRes.ErrorURI)
	}

	// Refreshes identity provider configuration and keys. Making sure we retrieved new
	// signing keys that may have been generated.
	if err := discovery.Run(config.Issuer); err != nil {
		return errors.Wrapf(err, "failed refreshing provider configuration from %q", config.Issuer)
	}

	newTokens := new(Tokens)
	newTokens.Access = refreshRes.AccessToken
	newTokens.ID = refreshRes.IDToken
	newTokens.Refresh = refreshRes.RefreshToken
	newTokens.Issuer = config.Issuer

	if err := newTokens.Verify(clientID, nonce); err != nil {
		return err
	}

	if err := newTokens.Write(); err != nil {
		return err
	}

	tks.Access = newTokens.Access
	tks.Refresh = newTokens.Refresh
	tks.ID = newTokens.ID
	tks.Issuer = newTokens.Issuer

	return nil
}

// hash helps prevent token substitution attacks by hashing a given token value and
// returning the left-most half of it.
// This function behaves as specified in the OpenID Connect spec for calculating
// at_hash and c_hash values. http://openid.net/specs/openid-connect-core-1_0.html#rfc.section.16.11
func hash(token string, alg string) string {
	var leftMostHalf []byte
	switch jose.SignatureAlgorithm(alg) {
	case jose.ES384, jose.RS384:
		sum := sha512.Sum384([]byte(token))
		leftMostHalf = sum[:(len(sum) / 2)]
	case jose.ES512, jose.RS512:
		sum := sha512.Sum512([]byte(token))
		leftMostHalf = sum[:(len(sum) / 2)]
	default:
		sum := sha512.Sum512_256([]byte(token))
		leftMostHalf = sum[:(len(sum) / 2)]
	}
	return base64.StdEncoding.EncodeToString(leftMostHalf)
}

// Delete removes all the tokens cached on disk.
func Delete() error {
	return os.Remove(tokensPath)
}
