# secp256k1 bindings for Go

## General info

The Go API mirrors the API of the C implementation. Therefore,
please consult `c-secp256k1/include/secp256k1.h` for documentation.
Going forward I plan to implement a new API that is more aligned
with the APIs from Go's standard lib crypto packages. Then, it makes
more sense to add a standalone documentation, and hopefully breaking
changes in the C implementation can be abstracted away.

## How to get and build

```bash
go get -d github.com/toxeus/go-secp256k1
cd $GOPATH/src/github.com/toxeus/go-secp256k1
git submodule update --init # not needed for Go >= 1.6
cd c-secp256k1
./autogen.sh && ./configure && make
cd ..
go install
```

## How to update

```bash
cd $GOPATH/src/github.com/toxeus/go-secp256k1
git submodule update
cd c-secp256k1
make distclean && ./autogen.sh && ./configure && make
cd ..
go clean && go install
```
