pragma circom 2.1.9;

template binaryCheck() {
    signal input in;
    signal output out;

    in * (in - 1 ) === 0;

    out <== in;
}
