package discovery

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	jose "gopkg.in/square/go-jose.v2"

	"github.com/hooklift/lift/config"
	"github.com/lift-plugins/auth/openidc/oauth2"
	"github.com/pkg/errors"
)

var jwksPath = filepath.Join(config.WorkDir, "jwks.json")

// SigningKeys represents the OpenID provider signing keys.
type SigningKeys struct {
	Keys map[string]jose.JSONWebKey `json:"keys"`
}

// Fetch downloads OpenID provider signing keys.
func (k *SigningKeys) Fetch(jwkURI string) error {
	resp, err := oauth2.Client.Get(jwkURI)
	if err != nil {
		return errors.Wrap(err, "failed to get OpenID provider signing keys.")
	}
	defer resp.Body.Close()

	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)) // limits reading to 1mb only.

	var keySet jose.JSONWebKeySet
	if err := decoder.Decode(&keySet); err != nil {
		return errors.Wrapf(err, "failed decoding signing keys received from %q", jwkURI)
	}

	k.Keys = make(map[string]jose.JSONWebKey, len(keySet.Keys))
	for _, key := range keySet.Keys {
		if !key.Valid() {
			// TODO(c4milo): send metric to alert Hooklift security team about this.
			log.Fatalf("JSON Web Key %q is not a valid crypto key \n", key.KeyID)
		}
		k.Keys[key.KeyID] = key
	}
	return nil
}

// Read loads cached OpenID provider signing keys.
func (k *SigningKeys) Read() error {
	data, err := ioutil.ReadFile(jwksPath)
	if err != nil {
		return errors.Wrapf(err, "failed reading OpenID provider config file at %q", jwksPath)
	}

	if err := json.Unmarshal(data, k); err != nil {
		return errors.Wrapf(err, "failed unmarshaling OpenID provider config file at %q", jwksPath)
	}
	return nil
}

// Key returns a cached key by its ID.
func (k *SigningKeys) Key(kid string) (jose.JSONWebKey, error) {
	v, ok := k.Keys[kid]
	if !ok {
		return jose.JSONWebKey{}, fmt.Errorf("signing key %q not found", kid)
	}
	return v, nil
}

// Write writes current keys to disk file.
func (k *SigningKeys) Write() error {
	data, err := json.MarshalIndent(k, "", "\t")
	if err != nil {
		return errors.Wrap(err, "failed marshaling OpenID provider signing keys")
	}

	if err := ioutil.WriteFile(jwksPath, data, os.FileMode(0600)); err != nil {
		return errors.Wrapf(err, "failed writing OpenID provider signing keys %q", jwksPath)
	}
	return nil
}
