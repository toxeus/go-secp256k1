package secp256k1

// #include "c-secp256k1/include/secp256k1.h"
// #cgo LDFLAGS: ../../../github.com/toxeus/go-secp256k1/c-secp256k1/.libs/libsecp256k1.a -lgmp 
import "C"
import "unsafe"

// The Go API mirrors the API of the C implementation. Therefore,
// please consult c-secp256k1/include/secp256k1.h for documentation.
// Going forward I plan to implement a new API that is more aligned
// with the APIs from Go's standard lib crypto packages. Then, it makes
// more sense to have a good documentation, and hopefully breaking
// changes in the C implementation can be abstracted away.

const hashLen int = 32

type Context struct {
	context *C.secp256k1_context
}

func (c *Context) Create() {
	flag := C.uint(C.SECP256K1_CONTEXT_VERIFY | C.SECP256K1_CONTEXT_SIGN)
	c.context = C.secp256k1_context_create(flag)
}

func (c *Context) Destroy() {
	C.secp256k1_context_destroy(c.context)
}

type Pubkey struct {
	pubkey *C.secp256k1_pubkey
}

type Signature struct {
	sig *C.secp256k1_ecdsa_signature
}

func Pubkey_create(context Context, seckey [32]byte, compressed bool) (Pubkey, bool) {
	pubkey := Pubkey{
		pubkey: &C.secp256k1_pubkey{},
	}
	success := C.secp256k1_ec_pubkey_create(
		context.context,
		pubkey.pubkey,
		cBuf(seckey[:]))
	return pubkey, goBool(success)
}

func Seckey_verify(context Context, seckey [32]byte) bool {
	success := C.secp256k1_ec_seckey_verify(context.context, cBuf(seckey[:]))
	return goBool(success)
}

func Sign(context Context, msgHash [hashLen]byte, seckey [32]byte, nonce *[32]byte) (Signature, bool) {
	sig := Signature{
		sig: &C.secp256k1_ecdsa_signature{},
	}
	success := C.secp256k1_ecdsa_sign(
		context.context,
		sig.sig,
		cBuf(msgHash[:]),
		cBuf(seckey[:]),
		nil,
		unsafe.Pointer(nonce))
	return sig, goBool(success)
}

func Verify(context Context, msgHash [hashLen]byte, sig Signature, pubkey Pubkey) bool {
	success := C.secp256k1_ecdsa_verify(
		context.context,
		sig.sig,
		cBuf(msgHash[:]),
		pubkey.pubkey)
	return goBool(success)
}

func goBool(success C.int) bool {
	return success == 1
}

func cBuf(goSlice []byte) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(&goSlice[0]))
}
