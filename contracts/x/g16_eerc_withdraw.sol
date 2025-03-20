// SPDX-License-Identifier: AML
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

// 2019 OKIMS

pragma solidity ^0.8.0;

library Pairing {
    uint256 constant PRIME_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }

    /*
     * @return The negation of p, i.e. p.plus(p.negate()) should be zero.
     */
    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        if (p.X == 0 && p.Y == 0) {
            return G1Point(0, 0);
        } else {
            return G1Point(p.X, PRIME_Q - (p.Y % PRIME_Q));
        }
    }

    /*
     * @return The sum of two points of G1
     */
    function plus(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint256[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success
            case 0 { invalid() }
        }

        require(success, "pairing-add-failed");
    }

    /*
     * Same as plus but accepts raw input instead of struct
     * @return The sum of two points of G1, one is represented as array
     */
    function plus_raw(uint256[4] memory input, G1Point memory r) internal view {
        bool success;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success
            case 0 { invalid() }
        }

        require(success, "pairing-add-failed");
    }

    /*
     * @return The product of a point on G1 and a scalar, i.e.
     *         p == p.scalar_mul(1) and p.plus(p) == p.scalar_mul(2) for all
     *         points p.
     */
    function scalar_mul(G1Point memory p, uint256 s) internal view returns (G1Point memory r) {
        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success
            case 0 { invalid() }
        }
        require(success, "pairing-mul-failed");
    }

    /*
     * Same as scalar_mul but accepts raw input instead of struct,
     * Which avoid extra allocation. provided input can be allocated outside and re-used multiple times
     */
    function scalar_mul_raw(uint256[3] memory input, G1Point memory r) internal view {
        bool success;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success
            case 0 { invalid() }
        }
        require(success, "pairing-mul-failed");
    }

    /* @return The result of computing the pairing check
     *         e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
     *         For example,
     *         pairing([P1(), P1().negate()], [P2(), P2()]) should return true.
     */
    function pairing(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2,
        G1Point memory c1,
        G2Point memory c2,
        G1Point memory d1,
        G2Point memory d2
    ) internal view returns (bool) {
        G1Point[4] memory p1 = [a1, b1, c1, d1];
        G2Point[4] memory p2 = [a2, b2, c2, d2];
        uint256 inputSize = 24;
        uint256[] memory input = new uint256[](inputSize);

        for (uint256 i = 0; i < 4; i++) {
            uint256 j = i * 6;
            input[j + 0] = p1[i].X;
            input[j + 1] = p1[i].Y;
            input[j + 2] = p2[i].X[0];
            input[j + 3] = p2[i].X[1];
            input[j + 4] = p2[i].Y[0];
            input[j + 5] = p2[i].Y[1];
        }

        uint256[1] memory out;
        bool success;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success
            case 0 { invalid() }
        }

        require(success, "pairing-opcode-failed");

        return out[0] != 0;
    }
}

contract x_WithdrawVerifier {
    using Pairing for *;

    error ProofInvalid();

    uint256 constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant PRIME_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct VerifyingKey {
        Pairing.G1Point alfa1;
        Pairing.G2Point beta2;
        Pairing.G2Point gamma2;
        Pairing.G2Point delta2;
    }
    // []G1Point IC (K in gnark) appears directly in verifyProof

    struct Proof {
        Pairing.G1Point A;
        Pairing.G2Point B;
        Pairing.G1Point C;
    }

    function verifyingKey() internal pure returns (VerifyingKey memory vk) {
        vk.alfa1 = Pairing.G1Point(
            uint256(9242396711108772471466890131549430127816189477685050942633761184331012071633),
            uint256(6408668045034894261762003938901722173157446832149376449264691860513431484816)
        );
        vk.beta2 = Pairing.G2Point(
            [
                uint256(11268297225275325001167530886845354526055845301384787317129269963702163928055),
                uint256(343282724710799080862748110869705638181694577887200046039256387444133102956)
            ],
            [
                uint256(2844479151314661796021973070020523247305971608443941577561610413616648385789),
                uint256(745632168863323467390157303279857946213173718482655914825716745904093644932)
            ]
        );
        vk.gamma2 = Pairing.G2Point(
            [
                uint256(12838849877438255059258477741413759938657752455997537171760190789463133041345),
                uint256(20220707282241169340782761640282690981903729368793320953440190819275651188132)
            ],
            [
                uint256(4379769347866748535415810076896094434015382399205476349288143211919592712262),
                uint256(18459381970055259665595198739954471323370644666743711863265285189708447243661)
            ]
        );
        vk.delta2 = Pairing.G2Point(
            [
                uint256(1896336847237723273943642785707966475529246539185336271070880497975042744308),
                uint256(9819398603718049902205574344808658676170846749462841644919072854797214438832)
            ],
            [
                uint256(11113537095716236229344353711635726742456408817160759278333848817016342411811),
                uint256(8071791722305231500827012680637877286465290912573140877727007445108143237718)
            ]
        );
    }

    // accumulate scalarMul(mul_input) into q
    // that is computes sets q = (mul_input[0:2] * mul_input[3]) + q
    function accumulate(
        uint256[3] memory mul_input,
        Pairing.G1Point memory p,
        uint256[4] memory buffer,
        Pairing.G1Point memory q
    ) internal view {
        // computes p = mul_input[0:2] * mul_input[3]
        Pairing.scalar_mul_raw(mul_input, p);

        // point addition inputs
        buffer[0] = q.X;
        buffer[1] = q.Y;
        buffer[2] = p.X;
        buffer[3] = p.Y;

        // q = p + q
        Pairing.plus_raw(buffer, q);
    }

    /*
     * @returns Whether the proof is valid given the hardcoded verifying key
     *          above and the public inputs
     */
    function _verifyProof(uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[16] calldata input)
        internal
        view
        returns (bool r)
    {
        Proof memory proof;
        proof.A = Pairing.G1Point(a[0], a[1]);
        proof.B = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        proof.C = Pairing.G1Point(c[0], c[1]);

        // Make sure that proof.A, B, and C are each less than the prime q
        require(proof.A.X < PRIME_Q, "verifier-aX-gte-prime-q");
        require(proof.A.Y < PRIME_Q, "verifier-aY-gte-prime-q");

        require(proof.B.X[0] < PRIME_Q, "verifier-bX0-gte-prime-q");
        require(proof.B.Y[0] < PRIME_Q, "verifier-bY0-gte-prime-q");

        require(proof.B.X[1] < PRIME_Q, "verifier-bX1-gte-prime-q");
        require(proof.B.Y[1] < PRIME_Q, "verifier-bY1-gte-prime-q");

        require(proof.C.X < PRIME_Q, "verifier-cX-gte-prime-q");
        require(proof.C.Y < PRIME_Q, "verifier-cY-gte-prime-q");

        // Make sure that every input is less than the snark scalar field
        for (uint256 i = 0; i < input.length; i++) {
            require(input[i] < SNARK_SCALAR_FIELD, "verifier-gte-snark-scalar-field");
        }

        VerifyingKey memory vk = verifyingKey();

        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);

        // Buffer reused for addition p1 + p2 to avoid memory allocations
        // [0:2] -> p1.X, p1.Y ; [2:4] -> p2.X, p2.Y
        uint256[4] memory add_input;

        // Buffer reused for multiplication p1 * s
        // [0:2] -> p1.X, p1.Y ; [3] -> s
        uint256[3] memory mul_input;

        // temporary point to avoid extra allocations in accumulate
        Pairing.G1Point memory q = Pairing.G1Point(0, 0);

        vk_x.X = uint256(10671954567709589307378955180820523507913906050648519147197669433472406628504); // vk.K[0].X
        vk_x.Y = uint256(12166640454628030698161686374795281315520333691652085915725418860343596851656); // vk.K[0].Y
        mul_input[0] = uint256(17681203351799022940209639782730121487257620840331604986883437715226088230775); // vk.K[1].X
        mul_input[1] = uint256(4937348499463455147838353656817198565918532823345708950123755401590264989485); // vk.K[1].Y
        mul_input[2] = input[0];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[1] * input[0]
        mul_input[0] = uint256(14637816268225063695588173085043092239276294468410372623031284151003709251808); // vk.K[2].X
        mul_input[1] = uint256(11296824883441967638603144032399603258630227956934835541374992488228251035863); // vk.K[2].Y
        mul_input[2] = input[1];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[2] * input[1]
        mul_input[0] = uint256(13069818188761005447084045761014081998179352867124388099656220790453231147170); // vk.K[3].X
        mul_input[1] = uint256(3567918811083584327491972658370901911980603830144447902209474743795713422223); // vk.K[3].Y
        mul_input[2] = input[2];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[3] * input[2]
        mul_input[0] = uint256(18274104972416241144914093874267855843457932587703137599372552185444119300985); // vk.K[4].X
        mul_input[1] = uint256(16392229044646830627194802518790908471446553334632766389129691695812636645522); // vk.K[4].Y
        mul_input[2] = input[3];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[4] * input[3]
        mul_input[0] = uint256(5446313339798103981863845198975134290282227479025031455958890438677406168455); // vk.K[5].X
        mul_input[1] = uint256(9993945364304726438135350175861772071669352355414804698720094398250179014453); // vk.K[5].Y
        mul_input[2] = input[4];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[5] * input[4]
        mul_input[0] = uint256(14395612136306736133683104618916822888429591145571281595466463066902320614704); // vk.K[6].X
        mul_input[1] = uint256(9001702578217454659810100007420287947046159983645456534783525529524589128817); // vk.K[6].Y
        mul_input[2] = input[5];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[6] * input[5]
        mul_input[0] = uint256(787011521582489865121628322756981915782160054994163854306331862981811040877); // vk.K[7].X
        mul_input[1] = uint256(1965731149749278066338651141527403946590074194325247739262966407723571101931); // vk.K[7].Y
        mul_input[2] = input[6];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[7] * input[6]
        mul_input[0] = uint256(17690859902634284554327107108037113216417735149653545668911308919222505224172); // vk.K[8].X
        mul_input[1] = uint256(21690050482441035303106854999248872009542584421005676720846991965624507142287); // vk.K[8].Y
        mul_input[2] = input[7];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[8] * input[7]
        mul_input[0] = uint256(8209658751719425208749219604139737729076726864255141239187656491604671591979); // vk.K[9].X
        mul_input[1] = uint256(16165450156626982824286383463652972838591884650650612594193222184967333615342); // vk.K[9].Y
        mul_input[2] = input[8];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[9] * input[8]
        mul_input[0] = uint256(7223954931906767466611300152657108486398711336909160168684606373402253572233); // vk.K[10].X
        mul_input[1] = uint256(12926592828128618366391087095055280920458716995434481268484704881308089680293); // vk.K[10].Y
        mul_input[2] = input[9];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[10] * input[9]
        mul_input[0] = uint256(13023268421416952545307372484059290509629411977742913469169665656450651687554); // vk.K[11].X
        mul_input[1] = uint256(13162612357790016481491989305874420302542614019419514000785697929995319602397); // vk.K[11].Y
        mul_input[2] = input[10];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[11] * input[10]
        mul_input[0] = uint256(2460123148372984302413973218368313659067373366409417608525814500640456758364); // vk.K[12].X
        mul_input[1] = uint256(13313975825066829652012002904956742046873470063905810771510817367710317639421); // vk.K[12].Y
        mul_input[2] = input[11];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[12] * input[11]
        mul_input[0] = uint256(3043506159568504649039467760731979550291643008333480263141688818679633522019); // vk.K[13].X
        mul_input[1] = uint256(20941955803008716953953988838349974017246045774401059140258211008142401052025); // vk.K[13].Y
        mul_input[2] = input[12];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[13] * input[12]
        mul_input[0] = uint256(6017999892746063659699099845583130111159537122108714801173289799918551066722); // vk.K[14].X
        mul_input[1] = uint256(12837299281291238677755135631242710701566660156482046979041898083383969441324); // vk.K[14].Y
        mul_input[2] = input[13];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[14] * input[13]
        mul_input[0] = uint256(13107380331082698193491463895202061982239273152019415324978472369850615286187); // vk.K[15].X
        mul_input[1] = uint256(13238160984548443363654568249616238646538290777733094792624445406420693370998); // vk.K[15].Y
        mul_input[2] = input[14];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[15] * input[14]
        mul_input[0] = uint256(9071921606952144364345159408880572832225836668976221764380465640539772117677); // vk.K[16].X
        mul_input[1] = uint256(16797216963684791568989265637404859227419808274138937625925837010750421563918); // vk.K[16].Y
        mul_input[2] = input[15];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[16] * input[15]

        return
            Pairing.pairing(Pairing.negate(proof.A), proof.B, vk.alfa1, vk.beta2, vk_x, vk.gamma2, proof.C, vk.delta2);
    }

    function verifyProof(uint256[8] calldata proof, uint256[16] calldata input) external view {
        uint256[2] memory a = [proof[0], proof[1]];
        uint256[2][2] memory b = [[proof[2], proof[3]], [proof[4], proof[5]]];
        uint256[2] memory c = [proof[6], proof[7]];

        bool isVerified = _verifyProof(a, b, c, input);
        if (!isVerified) {
            revert ProofInvalid();
        }
    }
}
