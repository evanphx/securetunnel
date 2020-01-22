package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/hashicorp/securetunnel"
)

var (
	fToken = flag.String("token", "", "the access token")
	fGen   = flag.String("gen", "", "generate a new tunnel against server and output details")
	fDesc  = flag.String("desc", "", "description to apply to the tunnel when created")
	fJson  = flag.Bool("json", false, "output gen results in json")
)

func main() {
	flag.Parse()

	if *fGen != "" {
		var opts securetunnel.TunnelOptions
		opts.Host = *fGen

		if *fDesc != "" {
			opts.Description = *fDesc
		}

		params, err := securetunnel.CreateTunnel(opts)
		if err != nil {
			log.Fatal(err)
		}

		if *fJson {
			out := struct {
				TunnelId    string `json:"tunnel_id"`
				SourceToken string `json:"source_token"`
				DestToken   string `json:"dest_token"`
			}{
				TunnelId:    params.TunnelID,
				SourceToken: params.SourceToken,
				DestToken:   params.DestinationToken,
			}

			json.NewEncoder(os.Stdout).Encode(out)
		} else {
			fmt.Printf("Tunnel:            %s / %s\n", params.TunnelID, params.TunnelARN)
			fmt.Printf("Source Token:      %s\n", params.SourceToken)
			fmt.Printf("Destination Token: %s\n", params.DestinationToken)
		}
		return
	}

	tun, err := securetunnel.Open(*fToken)
	if err != nil {
		log.Fatal(err)
	}

	sig := make(chan os.Signal, 1)

	go func() {
		for {
			<-sig

			stat, err := tun.RequestStatus()
			if err == nil {
				fmt.Fprintf(os.Stderr, "Lifetime: %ds\nData Transfered: %d\n",
					stat.Lifetime, stat.DataTransfered)
			}
		}
	}()

	signal.Notify(sig, syscall.SIGUSR1)

	go io.Copy(tun, os.Stdin)
	io.Copy(os.Stdout, tun)
}
