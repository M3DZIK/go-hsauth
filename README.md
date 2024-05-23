# Handshake authentication

[HSAuth](https://hsauth.medzik.dev) is a user authentication algorithm created to 
eliminate the need to send the password or even its hash to the server. 
This makes authentication more secure because the password never touches the server.

## Getting started

First, add the library as a dependency to your golang project.

```
go get go.medzik.dev/hsauth
```

## Usage

### Generate keypair for server

```go
import "go.medzik.dev/crypto/x25519"

serverKeyPair, err := x25519.GenerateKey()
```

### Compute private key of a user

```go
import (
    "encoding/hex"
    "go.medzik.dev/crypto/x25519"
)

decodedUserPrivateKey, err := hex.DecodeString("")
userPrivateKey := x25519.PrivateKey(decodedUserPrivateKey)
userPublicKey, err := x25519.PublicFromPrivate(userPrivateKey)
```

### Calculate the HSAuth Key

```go
import "go.medzik.dev/hsauth"

hsAuthKey, err := hsauth.GenerateKeyV1(userPrivateKey, serverKeyPair.PublicKey)
```

### Validate the HSAuth Key on the server

```go
import (
    "fmt
    "go.medzik.dev/hsauth"
)

if hsauth.IsValidV1(*hsAuthKey, serverKeyPair.PrivateKey, userPublicKey) {
    fmt.Println("The HSAuth key is valid")
}
```
