package secp256k1

// #include "c-secp256k1/include/secp256k1.h"
// #cgo LDFLAGS: ../../../github.com/toxeus/go-secp256k1/c-secp256k1/.libs/libsecp256k1.a -lgmp 
import "C"
import "unsafe"

func Start() {
	C.secp256k1_start()
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
	success := C.secp256k1_ecdsa_pubkey_create(&pubkey[0],
		&pubkeylen,
		cBuf(seckey[:]),
		comp)
	return C.GoBytes(unsafe.Pointer(&pubkey[0]), pubkeylen), goBool(success)
}

func Seckey_verify(seckey [32]byte) bool {
	success := C.secp256k1_ecdsa_seckey_verify(cBuf(seckey[:]))
	return goBool(success)
}

func Pubkey_verify(pubkey []byte) bool {
	success := C.secp256k1_ecdsa_pubkey_verify(cBuf(pubkey), C.int(len(pubkey)))
	return goBool(success)
}

func Sign(msg []byte, seckey [32]byte, nonce [32]byte) ([]byte, bool) {
	var sig [72]C.uchar
	siglen := C.int(len(sig))
	success := C.secp256k1_ecdsa_sign(cBuf(msg),
		C.int(len(msg)),
		&sig[0],
		&siglen,
		cBuf(seckey[:]),
		cBuf(nonce[:]))
	return C.GoBytes(unsafe.Pointer(&sig[0]), siglen), goBool(success)
}

func Verify(msg []byte, sig []byte, pubkey []byte) bool {
	success := C.secp256k1_ecdsa_verify(cBuf(msg),
		C.int(len(msg)),
		cBuf(sig),
		C.int(len(sig)),
		cBuf(pubkey),
		C.int(len(pubkey)))
	// success can be also -1 and -2 to indicate invalid sig or invalid pubkey
	// for now we just ignore that
	return goBool(success)
}

func goBool(success C.int) bool {
	if success == 1 {
		return true
	}
	return false
}

func cBuf(goSlice []byte) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(&goSlice[0]))
}
