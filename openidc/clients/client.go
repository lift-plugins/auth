package clients

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/golang/protobuf/ptypes"
	api "github.com/hooklift/apis/go/identity"
	"github.com/hooklift/lift/config"
	"github.com/pkg/errors"
)

var clientPath = filepath.Join(config.WorkDir, "client.json")

// Client represents the OpenID Connect application used by Lift.
type Client struct {
	api.RegisterApp
	CreatedAt string `json:"created_at"`
}

// Write persist client data to disk.
func (c *Client) Write() error {
	c.CreatedAt = ptypes.TimestampString(c.ClientIdIssuedAt)

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
		return errors.Wrapf(err, "failed reading client config from %q", clientPath)
	}

	if err := json.Unmarshal(data, &c); err != nil {
		return errors.Wrapf(err, "failed unmarshaling client config from %q", clientPath)
	}
	return nil
}
