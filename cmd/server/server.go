package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/securetunnel"
)

var fAddr = flag.String("addr", ":24100", "address to listen on")

func main() {
	flag.Parse()

	serv, err := securetunnel.NewServer(hclog.L())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Listening on %s\n", *fAddr)
	http.ListenAndServe(*fAddr, serv)
}
