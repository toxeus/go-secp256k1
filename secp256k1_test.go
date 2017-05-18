package secp256k1_test

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/toxeus/go-secp256k1"
)

func Test_secp256k1(t *testing.T) {
	ctx := secp256k1.Context{}
	ctx.Create()
	defer ctx.Destroy()
	var seckey [32]byte
	io.ReadFull(rand.Reader, seckey[:])
	if isValid := secp256k1.Seckey_verify(ctx, seckey); !isValid {
		t.FailNow()
	}
	pubkey, _ := secp256k1.Pubkey_create(ctx, seckey, true)
	msg := make([]byte, 32)
	io.ReadFull(rand.Reader, msg)
	hash := sha256.Sum256(msg)
	var nonce [32]byte
	io.ReadFull(rand.Reader, nonce[:])
	sig, ok := secp256k1.Sign(ctx, hash, seckey, &nonce)
	if !ok {
		t.FailNow()
	}
	if ok := secp256k1.Verify(ctx, hash, sig, pubkey); !ok {
		t.FailNow()
	}
}
