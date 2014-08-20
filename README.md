How to build
============

    git submodule update --init
    cd c-secp256k1
    ./autogen.sh && ./configure && make
    cd ..
    go install
