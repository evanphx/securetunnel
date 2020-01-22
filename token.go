package securetunnel

import (
	"encoding/base64"
	"encoding/binary"

	uuid "github.com/satori/go.uuid"
)

func DecodeToken(token string) (*Token, []byte, []byte, error) {
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, nil, nil, err
	}

	sz := binary.BigEndian.Uint16(data)

	body := data[2 : sz+2]

	sig := data[sz+2:]

	var t Token

	err = t.Unmarshal(body)

	if err != nil {
		return nil, nil, nil, err
	}

	return &t, body, sig, nil
}

func (t *Token) TunnelID() string {
	u, err := uuid.FromBytes(t.Id)
	if err != nil {
		panic(err)
	}

	return u.String()
}
