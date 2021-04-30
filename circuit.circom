include "comparators.circom"
include "babyjub.circom"
include "gates.circom"
include "bitify.circom"
include "escalarmulany.circom"
//include "sha256.circom";
include "smthash_poseidon.circom"

template DiscreteLogAny() {
    signal private input in; 
    signal input G[2];
    signal output out[2];

    component pvkBits = Num2Bits(256);
    pvkBits.in <== in;
    component mulAny = EscalarMulAny(256);
    mulAny.p[0] <== G[0];
    mulAny.p[1] <== G[1];

    var i;
    for (i=0; i<256; i++) {
        mulAny.e[i] <== pvkBits.out[i];
    }
    out[0] <== mulAny.out[0];
    out[1] <== mulAny.out[1];
}

template DiscreteLogFixed() {
    signal private input in; 
    signal output out[2];

    component pvkBits = Num2Bits(256);
    pvkBits.in <== in;
    component mulAny = EscalarMulAny(256);
    mulAny.p[0] <== 995203441582195749578291179787384436505546430278305826713579947235728471134;
    mulAny.p[1] <== 5472060717959818805561601436314318772137091100104008585924551046643952123905;

    var i;
    for (i=0; i<256; i++) {
        mulAny.e[i] <== pvkBits.out[i];
    }
    out[0] <== mulAny.out[0];
    out[1] <== mulAny.out[1];
}


template ElGamalEncryption() {
    
    signal private input m[2];
    signal private input r;
    signal input pk[2];
    signal output c[4];


    //rG C1
    component dl1 = DiscreteLogFixed();
    dl1.in <== r;
    c[0] <== dl1.out[0];
    c[1] <== dl1.out[1];
    //rPK C2
    component dl2 = DiscreteLogAny();
    dl2.in <== r;
    dl2.G[0] <== pk[0];
    dl2.G[1] <== pk[1];
    
    component add = BabyAdd();
    add.x1 <== m[0];
    add.y1 <== m[1];
    add.x2 <== dl2.out[0];
    add.y2 <== dl2.out[1];
    c[2] <== add.xout;
    c[3] <== add.yout;

}

/*
template hashing() {
    signal input a;
    signal output out[256];
    var in[4];
  
    component nb = Num2Bits(4);
    nb.in <== a;
    for (var m = 0; m< 4; m++) {
            in[m] = nb.out[m]; 
    }   

    component H2 = Sha256(4);

    for (var v = 0; v< 4; v++) {
            H2.in[v] <== in[v]; 
    }

    for (var k = 0; k< 256; k++) {
            out[k] <== H2.out[k];
    } 

}
*/

template hashing() {   
   
    signal private input m[2];
    signal output out;  

    component s2 = SMTHash2();
    s2.R <== m[0];
    s2.L <== m[1];

    out <== s2.out;     

}

template EnS() {
    signal private input m[2];
    signal private input r;
    signal input pk[2];
    signal output c[4];
    signal output out;

    component E = ElGamalEncryption();
    E.m[0] <== m[0];
    E.m[1] <== m[1];
    E.r <== r;
    E.pk[0] <== pk[0];
    E.pk[1] <== pk[1];
    c[0] <== E.c[0];
    c[1] <== E.c[1];
    c[2] <== E.c[2];
    c[3] <== E.c[3];

    component s1 = hashing();
    s1.m[0] <== m[0];
    s1.m[1] <== m[1];
   
    out <== s1.out;  
}

component main = EnS()