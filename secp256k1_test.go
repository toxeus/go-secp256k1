package secp256k1_test

import (
	"crypto/rand"
	"github.com/toxeus/go-secp256k1"
	"io"
	"testing"
)

func Test_secp256k1(t *testing.T) {
	secp256k1.Start()
	defer secp256k1.Stop()
	var seckey [32]byte
	io.ReadFull(rand.Reader, seckey[:])
	if isValid := secp256k1.Seckey_verify(seckey); !isValid {
		t.FailNow()
	}
	pubkey, _ := secp256k1.Pubkey_create(seckey, true)
	if isValid := secp256k1.Pubkey_verify(pubkey); !isValid {
		t.FailNow()
	}
	msg := make([]byte, 32)
	io.ReadFull(rand.Reader, msg)
	var nonce [32]byte
	io.ReadFull(rand.Reader, nonce[:])
	sig, ok := secp256k1.Sign(msg, seckey, nonce)
	if !ok {
		t.FailNow()
	}
	if ok := secp256k1.Verify(msg, sig, pubkey); !ok {
		t.FailNow()
	}
}
