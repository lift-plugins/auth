package grpc

import (
	"log"
	"os"

	"google.golang.org/grpc/grpclog"
)

func init() {
	log.SetPrefix(" !      ")
	log.SetFlags(0)

	debug := os.Getenv("DEBUG")
	if debug == "0" || debug == "" {
		grpclog.SetLogger(new(nilLogger))
	}
}

type nilLogger struct{}

func (g *nilLogger) Fatal(args ...interface{})                 {}
func (g *nilLogger) Fatalf(format string, args ...interface{}) {}
func (g *nilLogger) Fatalln(args ...interface{})               {}
func (g *nilLogger) Print(args ...interface{})                 {}
func (g *nilLogger) Printf(format string, args ...interface{}) {}
func (g *nilLogger) Println(args ...interface{})               {}
