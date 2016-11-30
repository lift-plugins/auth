package tokens

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	jose "gopkg.in/square/go-jose.v2"

	"github.com/hooklift/lift/config"
	"github.com/lift-plugins/auth/openidc"
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

// Validate validates ID and Access tokens, according to:
// http://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.3.7
// http://openid.net/specs/openid-connect-core-1_0.html#ImplicitTokenValidation
func (tks *Tokens) Validate(clientID, nonce string) error {
	idToken, err := Decode(tks.ID)
	if err != nil {
		return err
	}

	if idToken.Nonce != nonce {
		return errors.New("ID token nonce does not match nonce value sent in request")
	}

	if idToken.Issuer != tks.Issuer {
		return errors.New("issuer in ID token does not match the identity provider originally used")
	}

	found := false
	for _, aud := range idToken.Audience {
		if clientID == aud {
			found = true
		}
	}

	if !found {
		return errors.New("ID token audience does not contain Lift CLI")
	}

	if idToken.AuthorizedParty != "" && idToken.AuthorizedParty != openidc.ClientID {
		return errors.New("authorized party in ID token does not match client ID")
	}

	expires := time.Unix(idToken.Expires, 0)
	if time.Now().After(expires) {
		return errors.New("ID token has expired")
	}

	if tks.Access != "" && idToken.AtHash != "" {
		atHash := hash(tks.Access, idToken.Header.Algorithm)
		if atHash != idToken.AtHash {
			return errors.New("calculated access token hash value does not match the value declared in ID token")
		}
	}

	return nil
}

// RefreshTokenResponse holds the response from the OpenIDC Provider when refreshing access tokens.
type refreshTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    string `json:"expires_in"`
	IDToken      string `json:"id_token"`
	Error        string `json:"error"`
}

// RefreshIfExpired refreshes ID, Access and Refresh tokens using current refresh token.
func (tks *Tokens) RefreshIfExpired() error {
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
		"scope":         {accessToken.Scope},
		"nonce":         {nonce},
	}

	req, err := http.NewRequest(http.MethodPost, config.TokenEndpoint, strings.NewReader(formValues.Encode()))
	if err != nil {
		return errors.Wrapf(err, "failed preparing HTTP request")
	}

	req.SetBasicAuth(openidc.ClientID, openidc.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := oauth2.Client.Do(req)
	if err != nil {
		return errors.Wrapf(err, "failed refreshing access token")
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return errors.New("unexpected response status code")
	}

	refreshRes := new(refreshTokenResponse)
	if err := json.NewDecoder(resp.Body).Decode(refreshRes); err != nil {
		return errors.Wrapf(err, "failed unmarshaling response")
	}

	newTokens := new(Tokens)
	newTokens.Access = refreshRes.AccessToken
	newTokens.ID = refreshRes.IDToken
	newTokens.Refresh = refreshRes.RefreshToken
	newTokens.Issuer = config.Issuer

	if err := newTokens.Validate(openidc.ClientID, nonce); err != nil {
		return err
	}

	return newTokens.Write()
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
