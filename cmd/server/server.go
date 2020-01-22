package main

import (
	"flag"
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

	L := hclog.L().Named("tunserv")

	serv, err := securetunnel.NewServer(*fDB, L)
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

	L.Info("listening", "addr", *fAddr)
	http.ListenAndServe(*fAddr, serv)
}
