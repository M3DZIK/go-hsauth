package hsauth

import (
	"bytes"
	"encoding/hex"
	"go.medzik.dev/crypto/x25519"
)

// GenerateKeyV1 generates a new HSAuth Key between the user and the server.
func GenerateKeyV1(userPrivateKey x25519.PrivateKey, serverPublicKey x25519.PublicKey) (*Key, error) {
	key, err := x25519.ComputeSharedSecret(userPrivateKey, serverPublicKey)
	if err != nil {
		return nil, err
	}

	hexKey := hex.EncodeToString(key)

	return (*Key)(&hexKey), nil
}

// IsValidV1 checks if the given HSAuth Key is valid between the server and the user.
func IsValidV1(hsAuthKey Key, serverPrivateKey x25519.PrivateKey, userPublicKey x25519.PublicKey) bool {
	key, err := hex.DecodeString(string(hsAuthKey))
	if err != nil {
		return false
	}

	sharedSecret, err := x25519.ComputeSharedSecret(serverPrivateKey, userPublicKey)
	if err != nil {
		return false
	}

	return bytes.Equal(sharedSecret, key)
}
