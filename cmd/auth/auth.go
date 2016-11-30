package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/briandowns/spinner"
	docopt "github.com/docopt/docopt-go"
	"github.com/howeyc/gopass"

	"github.com/lift-plugins/auth"
)

// Version is defined in compilation time.
var (
	Version string
)

const usage = `
Hooklift Identity CLI.

Usage:
  auth login [--provider=ADDRESS:PORT]
  auth logout
  auth whoami
  auth tokens
  auth -h | --help
  auth --version

Commands:
  login                                    Signs you into Hooklift.
  logout                                   Clears locally stored tokens.
  whoami                                   Displays currently signed user.
  tokens                                   Shows ID and Access tokens.

Options:
  -p, --provider=ADDRESS:PORT              The identity provider address. [default: id.hooklift.io:443]
  -h, --help                               Shows this screen.
  --version                                Shows version of this plugin.
`

// DEBUG determines whether or not DEBUG is active.
var DEBUG bool

func main() {
	debug := os.Getenv("DEBUG")
	if debug == "1" || debug != "" {
		DEBUG = true
	}

	args, err := docopt.Parse(usage, nil, true, Version, false, true)
	if err != nil {
		if v, ok := err.(*docopt.LanguageError); ok {
			log.Fatalf("DocOpt usage definition error: %s\n", v)
		}

		log.Fatalf("%+v", err)
	}

	if args["login"].(bool) {
		signIn(args)
		return
	}

	if args["logout"].(bool) {
		signOut(args)
	}

	if args["whoami"].(bool) {
		whoami(args)
	}

	if args["tokens"].(bool) {
		tokens(args)
	}
}

// signIn authenticates the user and returns the received identity token.
func signIn(args map[string]interface{}) {
	var email string
	address := args["--provider"].(string)
	fmt.Printf("Enter credentials for %s\n", address)

Email:
	fmt.Print("Email: ")
	fmt.Scanln(&email)
	if email == "" {
		goto Email
	}

Password:
	fmt.Print("Password: ")
	password, err := gopass.GetPasswdMasked()
	if err != nil {
		panic(err)
	}

	if len(password) == 0 {
		goto Password
	}

	someSet := []string{"● ○ ○", "○ ● ○", "○ ○ ●"}
	s := spinner.New(someSet, 200*time.Millisecond)
	s.Start()

	if err := auth.SignIn(email, string(password[:]), address); err != nil {
		s.Stop()
		fmt.Print("\r")
		log.Fatalln(err)
	}

	fmt.Println("\rSigned in successfully.")
}

// signOut terminates the user session with the OpenID Provider.
func signOut(args map[string]interface{}) {
	address := args["--provider"].(string)
	auth.SignOut(address)

	fmt.Println("Signed out successfully.")
}

// whoami prints the email of the user currently logged.
func whoami(args map[string]interface{}) {
	email, err := auth.WhoAmI()
	if err != nil {
		if DEBUG {
			log.Fatalln(err)
		}
		log.Fatalln("Not signed in")
	}

	fmt.Println(email)
}

// token prints the ID and Access tokens of the currently logged user.
func tokens(args map[string]interface{}) {
	idToken, accessToken, err := auth.Tokens()
	if err != nil {
		if DEBUG {
			log.Fatalln(err)
		}

		log.Fatalln("No tokens found. Please sign in first.")
	}

	fmt.Printf("ID Token: %s\n\n", idToken)
	fmt.Printf("Access Token: %s\n", accessToken)
}
