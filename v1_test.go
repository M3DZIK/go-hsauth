package hsauth_test

import (
	"go.medzik.dev/crypto/argon2id"
	"go.medzik.dev/crypto/x25519"
	"go.medzik.dev/hsauth"
	"testing"
)

func TestGenerateKeyV1(t *testing.T) {
	serverKeyPair, err := x25519.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	argon2Hasher := argon2id.Hasher{
		Memory:      32 * 1024,
		Iterations:  3,
		Parallelism: 3,
		HashLength:  32,
	}
	passwordHash := argon2Hasher.Hash([]byte("P@ssw0rd123!"), []byte("salt"))
	userPrivateKey := x25519.PrivateKey(passwordHash.Hash)
	userPublicKey, err := x25519.PublicFromPrivate(userPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	hsAuthKey, err := hsauth.GenerateKeyV1(userPrivateKey, serverKeyPair.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	hsAuthKey2, err := hsauth.GenerateKeyV1(serverKeyPair.PrivateKey, userPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if *hsAuthKey != *hsAuthKey2 {
		t.Fatal("hsAuthKey != hsAuthKey2")
	}

	if !hsauth.IsValidV1(*hsAuthKey, serverKeyPair.PrivateKey, userPublicKey) {
		t.Fatal("failed to validate HSAuth Key")
	}
}
