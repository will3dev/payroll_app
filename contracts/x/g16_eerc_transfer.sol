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
    uint256 constant PRIME_Q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

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
    function plus(
        G1Point memory p1,
        G1Point memory p2
    ) internal view returns (G1Point memory r) {
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
            case 0 {
                invalid()
            }
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
            case 0 {
                invalid()
            }
        }

        require(success, "pairing-add-failed");
    }

    /*
     * @return The product of a point on G1 and a scalar, i.e.
     *         p == p.scalar_mul(1) and p.plus(p) == p.scalar_mul(2) for all
     *         points p.
     */
    function scalar_mul(
        G1Point memory p,
        uint256 s
    ) internal view returns (G1Point memory r) {
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
            case 0 {
                invalid()
            }
        }
        require(success, "pairing-mul-failed");
    }

    /*
     * Same as scalar_mul but accepts raw input instead of struct,
     * Which avoid extra allocation. provided input can be allocated outside and re-used multiple times
     */
    function scalar_mul_raw(
        uint256[3] memory input,
        G1Point memory r
    ) internal view {
        bool success;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success
            case 0 {
                invalid()
            }
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
            success := staticcall(
                sub(gas(), 2000),
                8,
                add(input, 0x20),
                mul(inputSize, 0x20),
                out,
                0x20
            )
            // Use "invalid" to make gas estimation work
            switch success
            case 0 {
                invalid()
            }
        }

        require(success, "pairing-opcode-failed");

        return out[0] != 0;
    }
}

contract x_TransferVerifier {
    using Pairing for *;

    error ProofInvalid();

    uint256 constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant PRIME_Q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

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
            uint256(
                7859607439538809822641844527976698613200936152493843789896632890140465031538
            ),
            uint256(
                19411656663738022077150586570520924055497458430856780708997661523923165235999
            )
        );
        vk.beta2 = Pairing.G2Point(
            [
                uint256(
                    11801106064323276223366533520119931468539709092699782441326688764997422075280
                ),
                uint256(
                    17175066134382284073367197711234012378747352224883288057388723792937184291757
                )
            ],
            [
                uint256(
                    783886236310384293048424461004189719373295580754606731768491971910059746013
                ),
                uint256(
                    2032228071411170327219787618299459666512491699612297561378721081602094012936
                )
            ]
        );
        vk.gamma2 = Pairing.G2Point(
            [
                uint256(
                    15843679970774278617035235598858962521240232187439518342322941465534507435316
                ),
                uint256(
                    15446534230877756110220070514465732436469942046183276390872584632266575888936
                )
            ],
            [
                uint256(
                    9031730628254223994076317244970635682001075559491621088458370118861377209185
                ),
                uint256(
                    20536295970726254971117522910822380771059940835483080739120511301659199783129
                )
            ]
        );
        vk.delta2 = Pairing.G2Point(
            [
                uint256(
                    15240637209230528395094209289911502448919186187075676153319469159280402974976
                ),
                uint256(
                    7566749686885693441563694343664273024783738891420947041108837511384681369538
                )
            ],
            [
                uint256(
                    20092385445225994193675157948028554913716287499239244461217276621751122339378
                ),
                uint256(
                    11662470520005687275903732637657040746248502446684650276582652014760196078333
                )
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
    function _verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[32] calldata input
    ) internal view returns (bool r) {
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
            require(
                input[i] < SNARK_SCALAR_FIELD,
                "verifier-gte-snark-scalar-field"
            );
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

        vk_x.X = uint256(
            16395636041259063997092315619699029812257525777283941011534468374065713219327
        ); // vk.K[0].X
        vk_x.Y = uint256(
            5491944085050931288608137702773399485719287663952777089646968318558885986497
        ); // vk.K[0].Y
        mul_input[0] = uint256(
            4854721492602586985717440108067347450923941055438515726696967457782399914726
        ); // vk.K[1].X
        mul_input[1] = uint256(
            14228668502016914704391962011151095283535187498971211297567461193664222986253
        ); // vk.K[1].Y
        mul_input[2] = input[0];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[1] * input[0]
        mul_input[0] = uint256(
            14536084024493338802028289370002366936287334283225829170409652755471842676726
        ); // vk.K[2].X
        mul_input[1] = uint256(
            1982369820590567220657694399244898110359435882315552248975303058537965915512
        ); // vk.K[2].Y
        mul_input[2] = input[1];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[2] * input[1]
        mul_input[0] = uint256(
            19982972633545786305612641915383514983634572727832258173088414095223122182890
        ); // vk.K[3].X
        mul_input[1] = uint256(
            13265175164092182385451263503955362620240712103598085629835044140917552828641
        ); // vk.K[3].Y
        mul_input[2] = input[2];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[3] * input[2]
        mul_input[0] = uint256(
            19650114773234518185022951843910581303900514379147343575050565231154369144929
        ); // vk.K[4].X
        mul_input[1] = uint256(
            6555959150186103583994732048531485656417533937432374171373662182756998428799
        ); // vk.K[4].Y
        mul_input[2] = input[3];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[4] * input[3]
        mul_input[0] = uint256(
            19800561919339750745849185318837518619020546954066430555674781377958007044935
        ); // vk.K[5].X
        mul_input[1] = uint256(
            11716452816714890675243001049534805351819603431005343365677958471534674867907
        ); // vk.K[5].Y
        mul_input[2] = input[4];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[5] * input[4]
        mul_input[0] = uint256(
            11420243345279845371349305369470088344823142809812254223275092515150501721552
        ); // vk.K[6].X
        mul_input[1] = uint256(
            6833364955979880701570109538236780509711466405700201765194610123328073694678
        ); // vk.K[6].Y
        mul_input[2] = input[5];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[6] * input[5]
        mul_input[0] = uint256(
            10882251932586506830123556737674409324928950020407412611490731863555217930143
        ); // vk.K[7].X
        mul_input[1] = uint256(
            20044784607981560520200746419150634117004330983677359664334195556034497557171
        ); // vk.K[7].Y
        mul_input[2] = input[6];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[7] * input[6]
        mul_input[0] = uint256(
            4897496633477503876038682236531806150155896719754469138245498005797472329552
        ); // vk.K[8].X
        mul_input[1] = uint256(
            15004226465221579151164464954006061478739346411070312695081603950546974928558
        ); // vk.K[8].Y
        mul_input[2] = input[7];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[8] * input[7]
        mul_input[0] = uint256(
            14770226752702556178740502801800326843428743081753702900148070857430221373952
        ); // vk.K[9].X
        mul_input[1] = uint256(
            8408737718034150778617293751893497633282226996332416036484325783261374700619
        ); // vk.K[9].Y
        mul_input[2] = input[8];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[9] * input[8]
        mul_input[0] = uint256(
            19646003263560206969979556739452973267877594610463907955055561617529735979685
        ); // vk.K[10].X
        mul_input[1] = uint256(
            12090800959097117784746815726007062627233042029587312756422727773509129746047
        ); // vk.K[10].Y
        mul_input[2] = input[9];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[10] * input[9]
        mul_input[0] = uint256(
            17992439222500527409506463647255926478408457213431830463874211582233921739691
        ); // vk.K[11].X
        mul_input[1] = uint256(
            1897413203182125091701381877417974706295246111685963841217386515928475541680
        ); // vk.K[11].Y
        mul_input[2] = input[10];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[11] * input[10]
        mul_input[0] = uint256(
            15476149190276802229441322759786053000206651072980532266005200213625426512851
        ); // vk.K[12].X
        mul_input[1] = uint256(
            10986305988265524681486585149741877397081230600235301306325971949769551277959
        ); // vk.K[12].Y
        mul_input[2] = input[11];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[12] * input[11]
        mul_input[0] = uint256(
            1873861128966407088548115720852034522900907042612080558182350240903850145116
        ); // vk.K[13].X
        mul_input[1] = uint256(
            3931138159779258102706004311240964813541531716144966594459979608017409471035
        ); // vk.K[13].Y
        mul_input[2] = input[12];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[13] * input[12]
        mul_input[0] = uint256(
            6192844148064288254775172536159665530360357583089464079903882517253022734879
        ); // vk.K[14].X
        mul_input[1] = uint256(
            9726418838988880234778407774577868555394205057513996062817815577471236111807
        ); // vk.K[14].Y
        mul_input[2] = input[13];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[14] * input[13]
        mul_input[0] = uint256(
            15194724204592850434440178321544821944434861530255702079118152594975321085800
        ); // vk.K[15].X
        mul_input[1] = uint256(
            9212154581547897099840191000999588225818519003601921582740484350892301535905
        ); // vk.K[15].Y
        mul_input[2] = input[14];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[15] * input[14]
        mul_input[0] = uint256(
            2213125540738341511041501254989796365806465706751976656096735065576285908342
        ); // vk.K[16].X
        mul_input[1] = uint256(
            17816912602976013757689841643752327362044974241109822121627023150556856341398
        ); // vk.K[16].Y
        mul_input[2] = input[15];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[16] * input[15]
        mul_input[0] = uint256(
            7629545646537547322571256397089014219621399505721194651200687735690237190260
        ); // vk.K[17].X
        mul_input[1] = uint256(
            20569011416030965643310236217299952950061835342001921122775753378890047562167
        ); // vk.K[17].Y
        mul_input[2] = input[16];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[17] * input[16]
        mul_input[0] = uint256(
            2818388013248698446511408315330205074022067279532876998710593917361871852705
        ); // vk.K[18].X
        mul_input[1] = uint256(
            10815667607577065989601349520722223470427389078343274453988753003833184251315
        ); // vk.K[18].Y
        mul_input[2] = input[17];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[18] * input[17]
        mul_input[0] = uint256(
            102562845947399905250113897650229203505891939613226762598855047354093705303
        ); // vk.K[19].X
        mul_input[1] = uint256(
            14853450581299431995300907931895777868418249885507018808638881879796282520969
        ); // vk.K[19].Y
        mul_input[2] = input[18];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[19] * input[18]
        mul_input[0] = uint256(
            12877649934232173683684143392150847694488605634989712406225090737188499943746
        ); // vk.K[20].X
        mul_input[1] = uint256(
            4538157548713521894050324915494519081086999359330106074208618652212196057358
        ); // vk.K[20].Y
        mul_input[2] = input[19];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[20] * input[19]
        mul_input[0] = uint256(
            21458032406098599665870512947689363737678159910962438986853912044005009425604
        ); // vk.K[21].X
        mul_input[1] = uint256(
            10130358547966350611977905070727323539169121266937129473396613840304223313964
        ); // vk.K[21].Y
        mul_input[2] = input[20];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[21] * input[20]
        mul_input[0] = uint256(
            14520893335657716865593370515061473962349263383411188489372967535386393377375
        ); // vk.K[22].X
        mul_input[1] = uint256(
            18449092590544900179672534892860097259656018516883353793409682302580320832698
        ); // vk.K[22].Y
        mul_input[2] = input[21];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[22] * input[21]
        mul_input[0] = uint256(
            8513406252183315032499352949850989390610496683133905002168073385858224292335
        ); // vk.K[23].X
        mul_input[1] = uint256(
            7593724955445096405885771908078991496901554248720768630713957049250454163559
        ); // vk.K[23].Y
        mul_input[2] = input[22];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[23] * input[22]
        mul_input[0] = uint256(
            13810900349755091160200643599316506735692132078233942904751814303292367567423
        ); // vk.K[24].X
        mul_input[1] = uint256(
            10960564813472675334291138852438517623087016597729012579014637117964050214169
        ); // vk.K[24].Y
        mul_input[2] = input[23];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[24] * input[23]
        mul_input[0] = uint256(
            2386777499471528276638907030152652585932315331282876579964104427663837522089
        ); // vk.K[25].X
        mul_input[1] = uint256(
            2775497181188165935699211233867847996588351995367206965080624436050390237337
        ); // vk.K[25].Y
        mul_input[2] = input[24];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[25] * input[24]
        mul_input[0] = uint256(
            1462891257493928656654331300669225748217779706717948482103869068210349684599
        ); // vk.K[26].X
        mul_input[1] = uint256(
            10934949667102654225365116426703073480395010911233294908780935675585685921901
        ); // vk.K[26].Y
        mul_input[2] = input[25];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[26] * input[25]
        mul_input[0] = uint256(
            19174304520178519999436052440569144341224145338204495352550302097754762731819
        ); // vk.K[27].X
        mul_input[1] = uint256(
            195363573309347440036710376389629449802285539873852496316830640251179633886
        ); // vk.K[27].Y
        mul_input[2] = input[26];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[27] * input[26]
        mul_input[0] = uint256(
            11781776113477001837036052521423583238775026012058573884887292253726240620939
        ); // vk.K[28].X
        mul_input[1] = uint256(
            13463234030511779704168738044354283354826322877854061324627740142553484981489
        ); // vk.K[28].Y
        mul_input[2] = input[27];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[28] * input[27]
        mul_input[0] = uint256(
            15231202946459408844693476812373024829460619322494165445408218390127034950484
        ); // vk.K[29].X
        mul_input[1] = uint256(
            8971218942551337820042061072873294305744042581879816437177979545339054831828
        ); // vk.K[29].Y
        mul_input[2] = input[28];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[29] * input[28]
        mul_input[0] = uint256(
            9543229239195299034760519477479569263075451678169470002394799741212428332589
        ); // vk.K[30].X
        mul_input[1] = uint256(
            12912479659837782204845227943575646391998559206914054459239441287694604848059
        ); // vk.K[30].Y
        mul_input[2] = input[29];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[30] * input[29]
        mul_input[0] = uint256(
            12554661219195119102071109090038196135760682948210006087985731481676251252653
        ); // vk.K[31].X
        mul_input[1] = uint256(
            1571452160869012958069827497519902103197014466413240699077177223585142913867
        ); // vk.K[31].Y
        mul_input[2] = input[30];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[31] * input[30]
        mul_input[0] = uint256(
            4212767568356804975291092253717402975856299457548694817788300414108138882481
        ); // vk.K[32].X
        mul_input[1] = uint256(
            9958777918015962770257019566692436459719906913510084546087510561291578426865
        ); // vk.K[32].Y
        mul_input[2] = input[31];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[32] * input[31]

        return
            Pairing.pairing(
                Pairing.negate(proof.A),
                proof.B,
                vk.alfa1,
                vk.beta2,
                vk_x,
                vk.gamma2,
                proof.C,
                vk.delta2
            );
    }

    function verifyProof(
        uint256[8] calldata proof,
        uint256[32] calldata input
    ) external view {
        uint256[2] memory a = [proof[0], proof[1]];
        uint256[2][2] memory b = [[proof[2], proof[3]], [proof[4], proof[5]]];
        uint256[2] memory c = [proof[6], proof[7]];

        bool isVerified = _verifyProof(a, b, c, input);
        if (!isVerified) {
            // revert("Invalid proof");
            revert ProofInvalid();
        }
    }
}
