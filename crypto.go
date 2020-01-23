package securetunnel

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)

func GenerateKey() (noise.DHKey, error) {
	return cipherSuite.GenerateKeypair(rand.Reader)
}

func PublicKey(key noise.DHKey) string {
	return base64.RawURLEncoding.EncodeToString(key.Public)
}

func PrivateKey(key noise.DHKey) string {
	return base64.RawURLEncoding.EncodeToString(key.Private)
}

func ParsePrivateKey(key string) (noise.DHKey, error) {
	data, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return noise.DHKey{}, err
	}

	var pubkey, privkey [32]byte

	copy(privkey[:], data)

	curve25519.ScalarBaseMult(&pubkey, &privkey)
	return noise.DHKey{Private: privkey[:], Public: pubkey[:]}, nil
}

func (t *Tunnel) SourceSetup(key noise.DHKey) error {
	var cfg noise.Config

	cfg.CipherSuite = cipherSuite
	cfg.Initiator = true

	if len(key.Private) == 0 {
		cfg.Pattern = noise.HandshakeNN
	} else {
		cfg.Pattern = noise.HandshakeKN
		cfg.StaticKeypair = key
	}

	hs, err := noise.NewHandshakeState(cfg)
	if err != nil {
		return err
	}

	t.hs = hs

	return nil
}

func (t *Tunnel) DestSetup(peer string) error {
	var cfg noise.Config

	cfg.CipherSuite = cipherSuite

	if peer == "" {
		cfg.Pattern = noise.HandshakeNN
	} else {
		key, err := base64.RawURLEncoding.DecodeString(peer)
		if err != nil {
			return err
		}

		cfg.Pattern = noise.HandshakeKN
		cfg.PeerStatic = key
	}

	hs, err := noise.NewHandshakeState(cfg)
	if err != nil {
		return err
	}

	t.hs = hs

	return nil
}

func (t *Tunnel) SourceNego() ([]byte, error) {
	data, _, _, err := t.hs.WriteMessage(nil, nil)
	return data, err
}

func (t *Tunnel) SourceFinished(src []byte) error {
	_, writeCS, readCS, err := t.hs.ReadMessage(nil, src)
	if err != nil {
		return err
	}

	t.writeCS = writeCS
	t.readCS = readCS

	return nil
}

func (t *Tunnel) DestNego(src []byte) ([]byte, error) {
	_, _, _, err := t.hs.ReadMessage(nil, src)
	if err != nil {
		return nil, err
	}

	data, readCS, writeCS, err := t.hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, err
	}

	t.writeCS = writeCS
	t.readCS = readCS

	return data, nil
}

func (t *Tunnel) Encrypt(data []byte) []byte {
	if t.writeCS == nil {
		return data
	}

	return t.writeCS.Encrypt(nil, nil, data)
}

func (t *Tunnel) Decrypt(data []byte) ([]byte, error) {
	if t.readCS == nil {
		return data, nil
	}

	return t.readCS.Decrypt(nil, nil, data)
}
