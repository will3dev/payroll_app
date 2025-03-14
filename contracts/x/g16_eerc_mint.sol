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

// solhint:disable-next-line compiler-version
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

contract x_MintVerifier {
    using Pairing for *;

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
            uint256(881623839766253939021574183861099456389933341955617513461802898919581684268),
            uint256(19399697043090689269086372995719204805353648269652824767920933141143276175943)
        );
        vk.beta2 = Pairing.G2Point(
            [
                uint256(7592560915535360045670409600607792926515643046413123645863356585477507122271),
                uint256(9286760022946449307763774609790009959844601626330581398553010918791111560983)
            ],
            [
                uint256(9525633320877475031025557787586309047786599810279757825416854138630874683354),
                uint256(3107989291521789241386817968305113425377299132500841389907812254344484497763)
            ]
        );
        vk.gamma2 = Pairing.G2Point(
            [
                uint256(14689298151362100292801986979788501643207637822324790449155373951948747262212),
                uint256(17127071328809416325310672434352158606886454974996778589730073287119905902237)
            ],
            [
                uint256(10901501552484622575266584722117651190265288065215682927515555595518146666450),
                uint256(1947067803923407199050391297169464635294490662843642374554727977806567700618)
            ]
        );
        vk.delta2 = Pairing.G2Point(
            [
                uint256(20372666164226639814702675343428615984171580545138647398567143589588431472746),
                uint256(9515275346909044602462589071435575385023544927775692267643685811182414884785)
            ],
            [
                uint256(17102180254788952836335609655066152936761037684596892093748561961911789593772),
                uint256(4208058946687509876390396334681683113650338414608103309737844274932424062789)
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
    function _verifyProof(uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[24] calldata input)
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

        vk_x.X = uint256(10943694487362234782777296434545502910322689565729065564757841835878886119454); // vk.K[0].X
        vk_x.Y = uint256(2774173390734183441461169276999021439995107812175239467252451117578265782278); // vk.K[0].Y
        mul_input[0] = uint256(15998584400517261934465952236840947968784818842991246995541767196278722227271); // vk.K[1].X
        mul_input[1] = uint256(15464163548039433486911874728072922969885996951526065334320521873668917758181); // vk.K[1].Y
        mul_input[2] = input[0];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[1] * input[0]
        mul_input[0] = uint256(21698661302955613351726951704445805221535618896000438783626881680946878505126); // vk.K[2].X
        mul_input[1] = uint256(21269237524518488515193568247498817702789101594196762264488368083030110238963); // vk.K[2].Y
        mul_input[2] = input[1];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[2] * input[1]
        mul_input[0] = uint256(15457553536557738643901487224256504461985260620869616290124607654976098150706); // vk.K[3].X
        mul_input[1] = uint256(853201114222224286656937547540418342410201544405680386743896680314418358896); // vk.K[3].Y
        mul_input[2] = input[2];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[3] * input[2]
        mul_input[0] = uint256(9193465613893444087499205696818198560817601898657904880292287201265034974392); // vk.K[4].X
        mul_input[1] = uint256(12533508739575611265583533202397058356987448419264866642143607856596478789619); // vk.K[4].Y
        mul_input[2] = input[3];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[4] * input[3]
        mul_input[0] = uint256(9205373314194329551924803188863910607353788853903746809553408741523190159915); // vk.K[5].X
        mul_input[1] = uint256(16044091194028404583481212995123261940331457450598341016882654714465557074624); // vk.K[5].Y
        mul_input[2] = input[4];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[5] * input[4]
        mul_input[0] = uint256(8430595761097212309813747331035360299913172285757649871319375993031652948561); // vk.K[6].X
        mul_input[1] = uint256(21168106739235602032989536638833933830827640677138292628459712187686998455829); // vk.K[6].Y
        mul_input[2] = input[5];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[6] * input[5]
        mul_input[0] = uint256(9341079984040839889199201513898936978977187638075378853208331287181820541734); // vk.K[7].X
        mul_input[1] = uint256(1649856137550584238161385285537652561313248416613423251524964623460095412935); // vk.K[7].Y
        mul_input[2] = input[6];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[7] * input[6]
        mul_input[0] = uint256(4533865721297492166757092589567225118784767011776650714842419107537697334740); // vk.K[8].X
        mul_input[1] = uint256(8415281739240078801511030265554078484790880596755446819677775736739513549271); // vk.K[8].Y
        mul_input[2] = input[7];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[8] * input[7]
        mul_input[0] = uint256(10875101161611989588330154596053877576005813853661664977130384712351812468688); // vk.K[9].X
        mul_input[1] = uint256(12528932220769302211041800842412870642167045207349056788982970630746389322017); // vk.K[9].Y
        mul_input[2] = input[8];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[9] * input[8]
        mul_input[0] = uint256(13051881982269782316435537321839114842545048050026923367543881566577940843095); // vk.K[10].X
        mul_input[1] = uint256(21756438481932940642136748565626602919952876396644052272827199399134373110525); // vk.K[10].Y
        mul_input[2] = input[9];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[10] * input[9]
        mul_input[0] = uint256(21595508759678740688070952822027419530947089834090651196527803053172946370351); // vk.K[11].X
        mul_input[1] = uint256(5046277937195495281459424552894198921192377680781392583802136136131491656707); // vk.K[11].Y
        mul_input[2] = input[10];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[11] * input[10]
        mul_input[0] = uint256(19919882302696561919190008224124656525401114801440745280005316077669919048801); // vk.K[12].X
        mul_input[1] = uint256(19839048045778184779801954362761729622837569829104493789169844138694736930456); // vk.K[12].Y
        mul_input[2] = input[11];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[12] * input[11]
        mul_input[0] = uint256(16395153267751014922143983872058996652417622987550990762561663241675512879985); // vk.K[13].X
        mul_input[1] = uint256(14163358904084133703052279910365822794533955728881751474237187006903017315789); // vk.K[13].Y
        mul_input[2] = input[12];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[13] * input[12]
        mul_input[0] = uint256(4311047566354256322042809255732503341336068092910494358118652968620346663080); // vk.K[14].X
        mul_input[1] = uint256(19635762109498734348846147430138675202679908728266572576466996108194730020324); // vk.K[14].Y
        mul_input[2] = input[13];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[14] * input[13]
        mul_input[0] = uint256(10513049997458490298058368948019765717294816566912689169568230083600712387928); // vk.K[15].X
        mul_input[1] = uint256(3708866266676374145053263395760500306988224773509649860714816538233707546076); // vk.K[15].Y
        mul_input[2] = input[14];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[15] * input[14]
        mul_input[0] = uint256(16653576912871227353596064575001376319451522294410703585251481784052794654796); // vk.K[16].X
        mul_input[1] = uint256(10204006924892176891102077002267764856708882855558170150471118605560963762039); // vk.K[16].Y
        mul_input[2] = input[15];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[16] * input[15]
        mul_input[0] = uint256(12218374882739472404294389217790847842399638315738821732479975599705060937948); // vk.K[17].X
        mul_input[1] = uint256(21533063946685843563761211472332498301114683772908090764220114715158100906416); // vk.K[17].Y
        mul_input[2] = input[16];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[17] * input[16]
        mul_input[0] = uint256(4010718967007293123479039752462800865559973828090899829202714115010685508546); // vk.K[18].X
        mul_input[1] = uint256(6574313651848063871302313528207024011132234233313850624837840831365899828166); // vk.K[18].Y
        mul_input[2] = input[17];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[18] * input[17]
        mul_input[0] = uint256(7886393329186772925648796652736185065446852047415998327954010071762272382710); // vk.K[19].X
        mul_input[1] = uint256(12169012789393473832804657735186579812413955275864908859012488368426820752894); // vk.K[19].Y
        mul_input[2] = input[18];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[19] * input[18]
        mul_input[0] = uint256(5495255590094725451805598154570454865618905127858362568979313694703739706661); // vk.K[20].X
        mul_input[1] = uint256(3779720625132333264275104606702244742891253893459934705004555570907301488343); // vk.K[20].Y
        mul_input[2] = input[19];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[20] * input[19]
        mul_input[0] = uint256(10823271871183647337948229923205702546223165819152299984447568311090958405212); // vk.K[21].X
        mul_input[1] = uint256(8883947827086184246528751987064744165764350538575772390075475082465942021117); // vk.K[21].Y
        mul_input[2] = input[20];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[21] * input[20]
        mul_input[0] = uint256(12009882591719614816219958683893510844735782100630732182988118521104625734812); // vk.K[22].X
        mul_input[1] = uint256(13613828465732409713189225449500529394016057148454265116258597220344765146120); // vk.K[22].Y
        mul_input[2] = input[21];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[22] * input[21]
        mul_input[0] = uint256(3041567031727661002589653736180507870347545113987709677467361664416706983509); // vk.K[23].X
        mul_input[1] = uint256(1324657906547545157343185663555946863425305387804775663878541911404681051430); // vk.K[23].Y
        mul_input[2] = input[22];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[23] * input[22]
        mul_input[0] = uint256(3160967546864929735696564159267790806677585833500037454030893332611750673738); // vk.K[24].X
        mul_input[1] = uint256(20351017085941477761246528513981571012351169831509619384515180785949816486536); // vk.K[24].Y
        mul_input[2] = input[23];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[24] * input[23]

        return
            Pairing.pairing(Pairing.negate(proof.A), proof.B, vk.alfa1, vk.beta2, vk_x, vk.gamma2, proof.C, vk.delta2);
    }

    function verifyProof(uint256[8] calldata proof, uint256[24] calldata input) external view returns (bool) {
        uint256[2] memory a = [proof[0], proof[1]];
        uint256[2][2] memory b = [[proof[2], proof[3]], [proof[4], proof[5]]];
        uint256[2] memory c = [proof[6], proof[7]];

        return _verifyProof(a, b, c, input);
    }
}
