package discovery

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"io/ioutil"

	"strings"

	"github.com/hooklift/lift/config"
	"github.com/lift-plugins/auth/openidc/oauth2"
	"github.com/pkg/errors"
)

var configPath = filepath.Join(config.WorkDir, "openidc.json")

// ProviderConfig contains the OpenID Connect Provider configuration.
type ProviderConfig struct {
	Issuer                   string   `json:"issuer"`
	AuthzEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint            string   `json:"token_endpoint"`
	UserInfoEndpoint         string   `json:"userinfo_endpoint"`
	RevocationEndpoint       string   `json:"revocation_endpoint"`
	JWKSURI                  string   `json:"jwks_uri"`
	ResponseTypes            []string `json:"response_types_supported"`
	SubjectTypes             []string `json:"subject_types_supported"`
	IDTokenSigAlgs           []string `json:"id_token_signing_alg_values_supported"`
	Scopes                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
	Claims                   []string `json:"claims_supported"`
}

// Fetch downloads OpenID provider configuration and loads it in.
func (c *ProviderConfig) Fetch(address string) error {
	if !strings.HasPrefix(address, "http") {
		address = "https://" + address
	}

	url := fmt.Sprintf("%s/.well-known/openid-configuration", address)
	resp, err := oauth2.Client.Get(url)
	if err != nil {
		return errors.Wrapf(err, "failed retrieving identity server configuration from %q", url)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%q does not seem to implement OpenID Connect", address)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed discovering provider configuration. HTTP status: %d", resp.StatusCode)
	}

	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)) // limits reader to 1mb
	if err := decoder.Decode(c); err != nil {
		return errors.Wrapf(err, "failed decoding OpenID provider config from %q", address)
	}

	return nil
}

// Read loads the previously fetched OpenID provider configuration.
func (c *ProviderConfig) Read() error {
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return errors.Wrapf(err, "failed reading OpenID provider config file at %q", configPath)
	}

	if err := json.Unmarshal(data, c); err != nil {
		return errors.Wrapf(err, "failed unmarshaling OpenID provider config file at %q", configPath)
	}
	return nil
}

// Write stores the current configuration into its disk file.
func (c *ProviderConfig) Write() error {
	data, err := json.MarshalIndent(c, "", "\t")
	if err != nil {
		return errors.Wrap(err, "failed marshaling OpenID provider config")
	}

	if err := ioutil.WriteFile(configPath, data, os.FileMode(0600)); err != nil {
		return errors.Wrapf(err, "failed writing OpenID provider config to %q", configPath)
	}
	return nil
}
