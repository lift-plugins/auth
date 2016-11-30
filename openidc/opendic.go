package openidc

// These variables get injected when building the binary. Yes, we are exposing
// client secrets here. OpenID Connect and OAuth2 don't make it easier for us to
// not leak these credentials. However, the risk is mitigated in our identity server
// by strictly checking redirect URIs against those registered originally for the client
// before sending authorization codes. For native clients, it is up to user if she
// trusts the client asking for her credentials.
var (
	ClientID     string
	ClientSecret string
)
