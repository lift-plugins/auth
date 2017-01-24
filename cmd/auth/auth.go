package main

import (
	"fmt"
	"os"
	"strings"

	docopt "github.com/docopt/docopt-go"

	"github.com/hooklift/lift/ui"
	"github.com/lift-plugins/auth"
)

// Version is defined in compilation time.
var (
	Version string
)

const usage = `
Manages identity and authorization against Hooklift's Identity system.

Usage:
  auth login [--provider=ADDRESS:PORT]
  auth logout
  auth whoami
  auth tokens
  auth -h | --help
  auth -v | --verbose
  auth --version

Commands:
  login                                    Signs you into Hooklift.
  logout                                   Clears locally stored tokens.
  whoami                                   Displays currently signed user.
  tokens                                   Shows ID and Access tokens.

Options:
  -p --provider=ADDRESS:PORT              The identity provider address. [default: https://id.hooklift.io:443]
  -h --help                               Shows this screen.
  -v --version                            Shows version of this plugin.
`

func main() {
	args, err := docopt.Parse(usage, nil, false, "", false, false)
	if err != nil {
		ui.Debug("docopt failed to parse command: ->%#v<-", err)
		ui.Info(usage)
		os.Exit(1)
	}

	if args["--version"].(bool) {
		ui.Info(Version)
		return
	}

	if args["--help"].(bool) {
		ui.Info(usage)
		return
	}

	if args["login"].(bool) {
		signIn(args)
		return
	}

	if args["logout"].(bool) {
		signOut(args)
		return
	}

	if args["whoami"].(bool) {
		whoami(args)
		return
	}

	if args["tokens"].(bool) {
		tokens(args)
		return
	}
}

// signIn authenticates the user and returns the received identity token.
func signIn(args map[string]interface{}) {
	address := args["--provider"].(string)

	if !strings.HasPrefix(address, "http") {
		address = fmt.Sprintf("https://%s", address)
	}

	ui.Info("Enter credentials for %s\n", address)

	email := ui.Ask("Email: ")
	password := ui.AskPassword("Password: ")

	s := ui.Spinner()
	s.Start()
	if err := auth.SignIn(email, password, address); err != nil {
		s.Stop()
		ui.Info("\r")
		ui.Debug("%+v", err)
		ui.Fatal("%s", err)
	}

	ui.Info("\rSigned in successfully.\n")
}

// signOut terminates the user session with the OpenID Provider.
func signOut(args map[string]interface{}) {
	auth.SignOut()
	ui.Info("Signed out successfully.\n")
}

// whoami prints the email of the user currently logged.
func whoami(args map[string]interface{}) {
	email, err := auth.WhoAmI()
	if err != nil {
		ui.Debug("%+v", err)
		ui.Error("Not signed in")
	}

	ui.Info("%s\n", email)
}

// token prints the ID and Access tokens of the currently logged user.
func tokens(args map[string]interface{}) {
	idToken, accessToken, err := auth.Tokens()
	if err != nil {
		ui.Debug("%+v", err)
		ui.Fatal("No tokens found. Please sign in first.")
	}

	ui.Title("ID Token\n")
	ui.Info("%s\n", idToken)
	ui.Title("Access Token\n")
	ui.Info("%s\n", accessToken)
}
