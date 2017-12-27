package secp256k1

// #include "c-secp256k1/include/secp256k1.h"
// #cgo LDFLAGS: ${SRCDIR}/c-secp256k1/.libs/libsecp256k1.a -lgmp 
import "C"
import "unsafe"

// The Go API mirrors the API of the C implementation. Therefore,
// please consult c-secp256k1/include/secp256k1.h for documentation.
// Going forward I plan to implement a new API that is more aligned
// with the APIs from Go's standard lib crypto packages. Then, it makes
// more sense to have a good documentation, and hopefully breaking
// changes in the C implementation can be abstracted away.

const hashLen int = 32

func Start() {
	C.secp256k1_start(C.SECP256K1_START_VERIFY | C.SECP256K1_START_SIGN)
}

func Stop() {
	C.secp256k1_stop()
}

func Pubkey_create(seckey [32]byte, compressed bool) ([]byte, bool) {
	comp := C.int(0)
	bufsize := 65
	if compressed {
		comp = 1
		bufsize = 33
	}
	pubkey := make([]C.uchar, bufsize)
	pubkeylen := C.int(0)
	success := C.secp256k1_ec_pubkey_create(&pubkey[0],
		&pubkeylen,
		cBuf(seckey[:]),
		comp)
	return C.GoBytes(unsafe.Pointer(&pubkey[0]), pubkeylen), goBool(success)
}

func Seckey_verify(seckey [32]byte) bool {
	success := C.secp256k1_ec_seckey_verify(cBuf(seckey[:]))
	return goBool(success)
}

func Pubkey_verify(pubkey []byte) bool {
	success := C.secp256k1_ec_pubkey_verify(cBuf(pubkey), C.int(len(pubkey)))
	return goBool(success)
}

func Sign(msgHash [hashLen]byte, seckey [32]byte, nonce *[32]byte) ([]byte, bool) {
	var sig [72]C.uchar
	siglen := C.int(len(sig))
	success := C.secp256k1_ecdsa_sign(cBuf(msgHash[:]),
		&sig[0],
		&siglen,
		cBuf(seckey[:]),
		nil,
		unsafe.Pointer(nonce))
	return C.GoBytes(unsafe.Pointer(&sig[0]), siglen), goBool(success)
}

func Verify(msgHash [hashLen]byte, sig []byte, pubkey []byte) bool {
	success := C.secp256k1_ecdsa_verify(cBuf(msgHash[:]),
		cBuf(sig),
		C.int(len(sig)),
		cBuf(pubkey),
		C.int(len(pubkey)))
	// success can be also -1 and -2 to indicate invalid sig or invalid pubkey
	// for now we just ignore that
	return goBool(success)
}

func goBool(success C.int) bool {
	return success == 1
}

func cBuf(goSlice []byte) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(&goSlice[0]))
}
