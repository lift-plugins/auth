package tokens

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	jose "gopkg.in/square/go-jose.v2"

	"github.com/lift-plugins/auth/openidc/discovery"
	"github.com/pkg/errors"
)

// leeway is used to avoid late expirations due to client and server time mismatches.
const leeway = 10 * time.Second

// JSONWebToken represents a decoded OpenID Connect token.
type JSONWebToken struct {
	// ID is the token unique identifier.
	ID string `json:"jti,omitempty"`
	// Issuer identifies the entity that issued the token.
	Issuer string `json:"iss,omitempty"`
	// Subject identifies the principal that is the subject of the token.
	Subject string `json:"sub,omitempty"`
	// Audiencie identifies the recipients that the token is intended for.
	Audience []string `json:"aud,omitempty"`
	// Expires is the expiration time on or after which the JWT MUST NOT be accepted for processing.
	Expires int64 `json:"exp,omitempty"`
	// NotBefore identifies the time before which the JWT MUST NOT be accepted for processing
	NotBefore int64 `json:"nbf,omitempty"`
	// IssuedAt identifies the time at which the JWT was issued.
	IssuedAt int64 `json:"iat,omitempty"`

	// Open ID Connect fields
	// AuthTime Time when the authenticated End-User occurred
	AuthTime        int64  `json:"auth_time,omitempty"`
	Nonce           string `json:"nonce,omitempty"`
	AuthCtxClassRef string `json:"acr,omitempty"`
	AuthMethodRef   string `json:"amr,omitempty"`
	AuthorizedParty string `json:"azp,omitempty"`
	AtHash          string `json:"at_hash,omitempty"`
	CHash           string `json:"c_hash,omitempty"`
	Name            string `json:"name,omitempty"`
	Email           string `json:"email,omitempty"`
	EmailVerified   bool   `json:"email_verified,omitempty"`

	// Private claim set.
	Scope []string `json:"scope,omitempty"`
}

// Expired returns whether or not the token has expired.
func (t *JSONWebToken) Expired() bool {
	expiry := time.Unix(t.Expires, 0)
	if expiry.IsZero() {
		return false
	}

	return time.Now().After(expiry.Add(-leeway))
}

// Verify checks token signature and returns its payload and signature header.
func Verify(token string) (jose.Header, error) {
	var header jose.Header
	jws, err := jose.ParseSigned(token)
	if err != nil {
		return header, errors.Wrap(err, "failed parsing token signature")
	}

	if len(jws.Signatures) != 1 {
		return header, errors.New("too many or too few signatures")
	}

	keys := new(discovery.SigningKeys)
	if err := keys.Read(); err != nil {
		return header, err
	}

	header = jws.Signatures[0].Header
	jwk, err := keys.Key(header.KeyID)
	if err != nil {
		return header, err
	}

	_, err = jws.Verify(&jwk)
	if err != nil {
		return header, errors.Wrap(err, "token integrity couldn't be verified")
	}

	return header, nil
}

// Decode decodes a base64 encoded JWT token, without verifying its signature.
func Decode(token string) (*JSONWebToken, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("compact JWS format must have three parts")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.Wrap(err, "failed decoding token payload")
	}

	jwt := new(JSONWebToken)
	if err := json.Unmarshal(payload, jwt); err != nil {
		return nil, errors.Wrap(err, "failed decoding token")
	}

	return jwt, nil
}
