package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/securetunnel"
)

var fAddr = flag.String("addr", ":24100", "address to listen on")
var fDB = flag.String("db", "./sessions.db", "path to sessions database file")

func main() {
	flag.Parse()

	serv, err := securetunnel.NewServer(*fDB, hclog.L())
	if err != nil {
		log.Fatal(err)
	}

	c := make(chan os.Signal, 1)

	signal.Notify(c, os.Interrupt)

	go func() {
		<-c
		serv.Close()
		os.Exit(1)
	}()

	fmt.Printf("Listening on %s\n", *fAddr)
	http.ListenAndServe(*fAddr, serv)
}
