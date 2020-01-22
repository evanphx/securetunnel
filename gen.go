package securetunnel

import (
	"encoding/json"
	"net/http"
)

type TunnelOptions struct {
	Region      string
	Tags        map[string]string
	Description string
}

type TunnelParams struct {
	TunnelID         string
	TunnelARN        string
	SourceToken      string
	DestinationToken string
}

func CreateTunnel(opts TunnelOptions) (*TunnelParams, error) {
	resp, err := http.Get("http://localhost:24100/create-tunnel")
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	var response struct {
		TunnelID    string `json:"tunnel-id"`
		SourceToken string `json:"source-token"`
		DestToken   string `json:"destination-token"`
	}

	json.NewDecoder(resp.Body).Decode(&response)

	var params TunnelParams

	params.TunnelID = response.TunnelID
	params.TunnelARN = response.TunnelID
	params.SourceToken = response.SourceToken
	params.DestinationToken = response.DestToken

	return &params, nil
}
