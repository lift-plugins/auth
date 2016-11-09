package oauth2

import (
	"net/http"
	"time"
)

// Client is a preconfigured HTTP client, with a sensible timeout.
var Client *http.Client

func init() {
	Client = &http.Client{
		// Timeout for the entire request phase: Dialing, TLS handshake,
		// sending the HTTP request, getting response headers and body. It is also a DEADLINE,
		// not the usual timeouts we are all used to, which resets every time there is activity
		// in the connection.
		Timeout: time.Second * 30,
		// Avoids the client following redirects.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
