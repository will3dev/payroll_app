// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title Groth16 verifier template.
/// @author Remco Bloemen
/// @notice Supports verifying Groth16 proofs. Proofs can be in uncompressed
/// (256 bytes) and compressed (128 bytes) format. A view function is provided
/// to compress proofs.
/// @notice See <https://2π.com/23/bn254-compression> for further explanation.
contract MintVerifier {
    /// Some of the provided public input values are larger than the field modulus.
    /// @dev Public input elements are not automatically reduced, as this is can be
    /// a dangerous source of bugs.
    error PublicInputNotInField();

    /// The proof is invalid.
    /// @dev This can mean that provided Groth16 proof points are not on their
    /// curves, that pairing equation fails, or that the proof is not for the
    /// provided public input.
    error ProofInvalid();

    // Addresses of precompiles
    uint256 constant PRECOMPILE_MODEXP = 0x05;
    uint256 constant PRECOMPILE_ADD = 0x06;
    uint256 constant PRECOMPILE_MUL = 0x07;
    uint256 constant PRECOMPILE_VERIFY = 0x08;

    // Base field Fp order P and scalar field Fr order R.
    // For BN254 these are computed as follows:
    //     t = 4965661367192848881
    //     P = 36⋅t⁴ + 36⋅t³ + 24⋅t² + 6⋅t + 1
    //     R = 36⋅t⁴ + 36⋅t³ + 18⋅t² + 6⋅t + 1
    uint256 constant P =
        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
    uint256 constant R =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    // Extension field Fp2 = Fp[i] / (i² + 1)
    // Note: This is the complex extension field of Fp with i² = -1.
    //       Values in Fp2 are represented as a pair of Fp elements (a₀, a₁) as a₀ + a₁⋅i.
    // Note: The order of Fp2 elements is *opposite* that of the pairing contract, which
    //       expects Fp2 elements in order (a₁, a₀). This is also the order in which
    //       Fp2 elements are encoded in the public interface as this became convention.

    // Constants in Fp
    uint256 constant FRACTION_1_2_FP =
        0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea4;
    uint256 constant FRACTION_27_82_FP =
        0x2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5;
    uint256 constant FRACTION_3_82_FP =
        0x2fcd3ac2a640a154eb23960892a85a68f031ca0c8344b23a577dcf1052b9e775;

    // Exponents for inversions and square roots mod P
    uint256 constant EXP_INVERSE_FP =
        0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD45; // P - 2
    uint256 constant EXP_SQRT_FP =
        0xC19139CB84C680A6E14116DA060561765E05AA45A1C72A34F082305B61F3F52; // (P + 1) / 4;

    // Groth16 alpha point in G1
    uint256 constant ALPHA_X =
        15465025267895251837643573395247504661318652395550615480190819361228662908527;
    uint256 constant ALPHA_Y =
        1023273314880257678066679944240432225884464270432836019227573660859817725679;

    // Groth16 beta point in G2 in powers of i
    uint256 constant BETA_NEG_X_0 =
        13602989511321134885866895267053381154982051080574648953143036897816794795619;
    uint256 constant BETA_NEG_X_1 =
        21067680791790786032908160891138636763285340745910391852538151554928537360269;
    uint256 constant BETA_NEG_Y_0 =
        4535320670753685001596661569174742294089446314128202911485320057040685654672;
    uint256 constant BETA_NEG_Y_1 =
        1598324054095704272368875126135724866756571194127904704339520872341748547589;

    // Groth16 gamma point in G2 in powers of i
    uint256 constant GAMMA_NEG_X_0 =
        11983367217761004262118174755977075553969080401893741678153455251649864081211;
    uint256 constant GAMMA_NEG_X_1 =
        1969165340664626032961679841443684949662303806780521846545812009624785447144;
    uint256 constant GAMMA_NEG_Y_0 =
        2171567678658093909184059013612251267927142909186362145653268251783960311259;
    uint256 constant GAMMA_NEG_Y_1 =
        5654038153439367400154487424983020592238115565041764210318558213147559913775;

    // Groth16 delta point in G2 in powers of i
    uint256 constant DELTA_NEG_X_0 =
        4682993027012428623558205854147364730443124641058697150075193828777098931801;
    uint256 constant DELTA_NEG_X_1 =
        21017824460321125199006231854816711768945349846747670684530277860589805263077;
    uint256 constant DELTA_NEG_Y_0 =
        20492761915730100975226450180181761247339993509288671203312393013701147610395;
    uint256 constant DELTA_NEG_Y_1 =
        16533177008717160827205300362553709695610701435981342939606538006967955543761;

    // Constant and public input points
    uint256 constant CONSTANT_X =
        20048115653660090067830292625663911436180309367631344371055182023781404666229;
    uint256 constant CONSTANT_Y =
        13713255710295481879202628390635713214890736081332187254788100139069219591900;
    uint256 constant PUB_0_X =
        2573824678352547719385111133185674074342729147060488343385512593874133754134;
    uint256 constant PUB_0_Y =
        18787571221759996190599369273582523810867310693266110989426965919190140074026;
    uint256 constant PUB_1_X =
        3757966939616111198068289961587953364466187235730175700710335947075914470822;
    uint256 constant PUB_1_Y =
        1928574391814101829024489825128529793703131210533419252081662272363543592164;
    uint256 constant PUB_2_X =
        13112004476065665417893500549614950992902096447203069038126994923206751160485;
    uint256 constant PUB_2_Y =
        15944542912866605321119260514851291779010695716120844208989737815401860419756;
    uint256 constant PUB_3_X =
        495692990419372784958846364851380075854809394784765388044022012039672752949;
    uint256 constant PUB_3_Y =
        10954585135994230947809148310350489265236965976217316297871442373554891159080;
    uint256 constant PUB_4_X =
        10920321069890654639597092821734366966074082155061366772400674636490673117101;
    uint256 constant PUB_4_Y =
        3952604442573231378104785104507223490709877962273261295511304506398439369335;
    uint256 constant PUB_5_X =
        3117711393820520767074618682983398151972171609272504491966914349566490475006;
    uint256 constant PUB_5_Y =
        5694675046561326690486983156069342301498133907948268153166736869557872162411;
    uint256 constant PUB_6_X =
        3572653280428673730016027903169628771433857111959085488771280254406468552431;
    uint256 constant PUB_6_Y =
        2591441810343437983205991986835712970615543159857984705039735069166660148238;
    uint256 constant PUB_7_X =
        3946469075474041870259645932414469771767926167434862652481921468297228558613;
    uint256 constant PUB_7_Y =
        6067576918621383060517985233804531453082342441901947011491993061796277871509;
    uint256 constant PUB_8_X =
        8486878158541811291715902355688754865058910429128761001509036685823388153404;
    uint256 constant PUB_8_Y =
        6201523313415089595316554452186866679752549228010321848135684442360526227196;
    uint256 constant PUB_9_X = 0;
    uint256 constant PUB_9_Y = 0;
    uint256 constant PUB_10_X =
        13554968845470212645559386445727472574781166584289570508174136214867026490996;
    uint256 constant PUB_10_Y =
        13604670040080378782504993006913658398262954540819848843539338923692049012614;
    uint256 constant PUB_11_X =
        7985618608019770091763900936503737741666609627399803927407294292624732400014;
    uint256 constant PUB_11_Y =
        18693313060804822358524491483871166316265574510941792717174779703399202654345;
    uint256 constant PUB_12_X =
        1509422517385948014427264295530748167737427026693579857931145661394071030047;
    uint256 constant PUB_12_Y =
        5379207931097109997167525126247596544567427100491712679585881533959449429575;
    uint256 constant PUB_13_X =
        18586837789494409635896354721554689503557026762698754073626456803617573910672;
    uint256 constant PUB_13_Y =
        19008159537533414935300785453502857160585839005379042380111874245578025751312;
    uint256 constant PUB_14_X =
        3812421728197802514335656152780274421773227010314623423557922985633830198945;
    uint256 constant PUB_14_Y =
        8214597780063304574853451333356268286230713616601190531695153643355067714528;
    uint256 constant PUB_15_X =
        8409868355874797768502365262461264287226127095506877135660106354185421250818;
    uint256 constant PUB_15_Y =
        16851530765192046179408827522531684523676379331386222007801136642418574567237;
    uint256 constant PUB_16_X =
        7120124750212362346880591724672499001081437515859511787376619344713058985402;
    uint256 constant PUB_16_Y =
        12084514821212379659185200174895057892684933598083894393578118251573923031354;
    uint256 constant PUB_17_X =
        16088300445037281430448738733031311509191445977924189713458351182844984262905;
    uint256 constant PUB_17_Y =
        2853632568684102017285954431437354485940067717115601751148218568694588983205;
    uint256 constant PUB_18_X =
        469255140072844028311965286401109234948697273231533376728566251216678411041;
    uint256 constant PUB_18_Y =
        1194672370734275499444483033507153223557679571862170650640184678872029607115;
    uint256 constant PUB_19_X =
        9162470878628525599823428499761091631696079224059348736403764035970641485205;
    uint256 constant PUB_19_Y =
        18337183708047077584638820488274214470062081030554000037698966116984917170168;
    uint256 constant PUB_20_X =
        3542825240029022244702211441608182471203698673026183742663012984389084667250;
    uint256 constant PUB_20_Y =
        11250515300585737552991303826550371095283606850954231620613427000048106492545;
    uint256 constant PUB_21_X =
        1580421183644692788270339877259844589507958283790071588652212862439417807033;
    uint256 constant PUB_21_Y =
        14013179197647029405842169476244059603346180184835339404712297465496297580807;
    uint256 constant PUB_22_X =
        4435126214787911896875237631756613861155415096463318073231744238069502968891;
    uint256 constant PUB_22_Y =
        17399816588840558495916306476581722924660421779983183333229881532929633455822;
    uint256 constant PUB_23_X =
        6520360730701872150581013222853731350614462685681489905006007984919302408326;
    uint256 constant PUB_23_Y =
        13988708159127602975876202377201733750863343129629215373770955585970158405725;

    /// Negation in Fp.
    /// @notice Returns a number x such that a + x = 0 in Fp.
    /// @notice The input does not need to be reduced.
    /// @param a the base
    /// @return x the result
    function negate(uint256 a) internal pure returns (uint256 x) {
        unchecked {
            x = (P - (a % P)) % P; // Modulo is cheaper than branching
        }
    }

    /// Exponentiation in Fp.
    /// @notice Returns a number x such that a ^ e = x in Fp.
    /// @notice The input does not need to be reduced.
    /// @param a the base
    /// @param e the exponent
    /// @return x the result
    function exp(uint256 a, uint256 e) internal view returns (uint256 x) {
        bool success;
        assembly ("memory-safe") {
            let f := mload(0x40)
            mstore(f, 0x20)
            mstore(add(f, 0x20), 0x20)
            mstore(add(f, 0x40), 0x20)
            mstore(add(f, 0x60), a)
            mstore(add(f, 0x80), e)
            mstore(add(f, 0xa0), P)
            success := staticcall(gas(), PRECOMPILE_MODEXP, f, 0xc0, f, 0x20)
            x := mload(f)
        }
        if (!success) {
            // Exponentiation failed.
            // Should not happen.
            revert ProofInvalid();
        }
    }

    /// Invertsion in Fp.
    /// @notice Returns a number x such that a * x = 1 in Fp.
    /// @notice The input does not need to be reduced.
    /// @notice Reverts with ProofInvalid() if the inverse does not exist
    /// @param a the input
    /// @return x the solution
    function invert_Fp(uint256 a) internal view returns (uint256 x) {
        x = exp(a, EXP_INVERSE_FP);
        if (mulmod(a, x, P) != 1) {
            // Inverse does not exist.
            // Can only happen during G2 point decompression.
            revert ProofInvalid();
        }
    }

    /// Square root in Fp.
    /// @notice Returns a number x such that x * x = a in Fp.
    /// @notice Will revert with InvalidProof() if the input is not a square
    /// or not reduced.
    /// @param a the square
    /// @return x the solution
    function sqrt_Fp(uint256 a) internal view returns (uint256 x) {
        x = exp(a, EXP_SQRT_FP);
        if (mulmod(x, x, P) != a) {
            // Square root does not exist or a is not reduced.
            // Happens when G1 point is not on curve.
            revert ProofInvalid();
        }
    }

    /// Square test in Fp.
    /// @notice Returns whether a number x exists such that x * x = a in Fp.
    /// @notice Will revert with InvalidProof() if the input is not a square
    /// or not reduced.
    /// @param a the square
    /// @return x the solution
    function isSquare_Fp(uint256 a) internal view returns (bool) {
        uint256 x = exp(a, EXP_SQRT_FP);
        return mulmod(x, x, P) == a;
    }

    /// Square root in Fp2.
    /// @notice Fp2 is the complex extension Fp[i]/(i^2 + 1). The input is
    /// a0 + a1 ⋅ i and the result is x0 + x1 ⋅ i.
    /// @notice Will revert with InvalidProof() if
    ///   * the input is not a square,
    ///   * the hint is incorrect, or
    ///   * the input coefficents are not reduced.
    /// @param a0 The real part of the input.
    /// @param a1 The imaginary part of the input.
    /// @param hint A hint which of two possible signs to pick in the equation.
    /// @return x0 The real part of the square root.
    /// @return x1 The imaginary part of the square root.
    function sqrt_Fp2(
        uint256 a0,
        uint256 a1,
        bool hint
    ) internal view returns (uint256 x0, uint256 x1) {
        // If this square root reverts there is no solution in Fp2.
        uint256 d = sqrt_Fp(addmod(mulmod(a0, a0, P), mulmod(a1, a1, P), P));
        if (hint) {
            d = negate(d);
        }
        // If this square root reverts there is no solution in Fp2.
        x0 = sqrt_Fp(mulmod(addmod(a0, d, P), FRACTION_1_2_FP, P));
        x1 = mulmod(a1, invert_Fp(mulmod(x0, 2, P)), P);

        // Check result to make sure we found a root.
        // Note: this also fails if a0 or a1 is not reduced.
        if (
            a0 != addmod(mulmod(x0, x0, P), negate(mulmod(x1, x1, P)), P) ||
            a1 != mulmod(2, mulmod(x0, x1, P), P)
        ) {
            revert ProofInvalid();
        }
    }

    /// Compress a G1 point.
    /// @notice Reverts with InvalidProof if the coordinates are not reduced
    /// or if the point is not on the curve.
    /// @notice The point at infinity is encoded as (0,0) and compressed to 0.
    /// @param x The X coordinate in Fp.
    /// @param y The Y coordinate in Fp.
    /// @return c The compresed point (x with one signal bit).
    function compress_g1(
        uint256 x,
        uint256 y
    ) internal view returns (uint256 c) {
        if (x >= P || y >= P) {
            // G1 point not in field.
            revert ProofInvalid();
        }
        if (x == 0 && y == 0) {
            // Point at infinity
            return 0;
        }

        // Note: sqrt_Fp reverts if there is no solution, i.e. the x coordinate is invalid.
        uint256 y_pos = sqrt_Fp(addmod(mulmod(mulmod(x, x, P), x, P), 3, P));
        if (y == y_pos) {
            return (x << 1) | 0;
        } else if (y == negate(y_pos)) {
            return (x << 1) | 1;
        } else {
            // G1 point not on curve.
            revert ProofInvalid();
        }
    }

    /// Decompress a G1 point.
    /// @notice Reverts with InvalidProof if the input does not represent a valid point.
    /// @notice The point at infinity is encoded as (0,0) and compressed to 0.
    /// @param c The compresed point (x with one signal bit).
    /// @return x The X coordinate in Fp.
    /// @return y The Y coordinate in Fp.
    function decompress_g1(
        uint256 c
    ) internal view returns (uint256 x, uint256 y) {
        // Note that X = 0 is not on the curve since 0³ + 3 = 3 is not a square.
        // so we can use it to represent the point at infinity.
        if (c == 0) {
            // Point at infinity as encoded in EIP196 and EIP197.
            return (0, 0);
        }
        bool negate_point = c & 1 == 1;
        x = c >> 1;
        if (x >= P) {
            // G1 x coordinate not in field.
            revert ProofInvalid();
        }

        // Note: (x³ + 3) is irreducible in Fp, so it can not be zero and therefore
        //       y can not be zero.
        // Note: sqrt_Fp reverts if there is no solution, i.e. the point is not on the curve.
        y = sqrt_Fp(addmod(mulmod(mulmod(x, x, P), x, P), 3, P));
        if (negate_point) {
            y = negate(y);
        }
    }

    /// Compress a G2 point.
    /// @notice Reverts with InvalidProof if the coefficients are not reduced
    /// or if the point is not on the curve.
    /// @notice The G2 curve is defined over the complex extension Fp[i]/(i^2 + 1)
    /// with coordinates (x0 + x1 ⋅ i, y0 + y1 ⋅ i).
    /// @notice The point at infinity is encoded as (0,0,0,0) and compressed to (0,0).
    /// @param x0 The real part of the X coordinate.
    /// @param x1 The imaginary poart of the X coordinate.
    /// @param y0 The real part of the Y coordinate.
    /// @param y1 The imaginary part of the Y coordinate.
    /// @return c0 The first half of the compresed point (x0 with two signal bits).
    /// @return c1 The second half of the compressed point (x1 unmodified).
    function compress_g2(
        uint256 x0,
        uint256 x1,
        uint256 y0,
        uint256 y1
    ) internal view returns (uint256 c0, uint256 c1) {
        if (x0 >= P || x1 >= P || y0 >= P || y1 >= P) {
            // G2 point not in field.
            revert ProofInvalid();
        }
        if ((x0 | x1 | y0 | y1) == 0) {
            // Point at infinity
            return (0, 0);
        }

        // Compute y^2
        // Note: shadowing variables and scoping to avoid stack-to-deep.
        uint256 y0_pos;
        uint256 y1_pos;
        {
            uint256 n3ab = mulmod(mulmod(x0, x1, P), P - 3, P);
            uint256 a_3 = mulmod(mulmod(x0, x0, P), x0, P);
            uint256 b_3 = mulmod(mulmod(x1, x1, P), x1, P);
            y0_pos = addmod(
                FRACTION_27_82_FP,
                addmod(a_3, mulmod(n3ab, x1, P), P),
                P
            );
            y1_pos = negate(
                addmod(FRACTION_3_82_FP, addmod(b_3, mulmod(n3ab, x0, P), P), P)
            );
        }

        // Determine hint bit
        // If this sqrt fails the x coordinate is not on the curve.
        bool hint;
        {
            uint256 d = sqrt_Fp(
                addmod(mulmod(y0_pos, y0_pos, P), mulmod(y1_pos, y1_pos, P), P)
            );
            hint = !isSquare_Fp(
                mulmod(addmod(y0_pos, d, P), FRACTION_1_2_FP, P)
            );
        }

        // Recover y
        (y0_pos, y1_pos) = sqrt_Fp2(y0_pos, y1_pos, hint);
        if (y0 == y0_pos && y1 == y1_pos) {
            c0 = (x0 << 2) | (hint ? 2 : 0) | 0;
            c1 = x1;
        } else if (y0 == negate(y0_pos) && y1 == negate(y1_pos)) {
            c0 = (x0 << 2) | (hint ? 2 : 0) | 1;
            c1 = x1;
        } else {
            // G1 point not on curve.
            revert ProofInvalid();
        }
    }

    /// Decompress a G2 point.
    /// @notice Reverts with InvalidProof if the input does not represent a valid point.
    /// @notice The G2 curve is defined over the complex extension Fp[i]/(i^2 + 1)
    /// with coordinates (x0 + x1 ⋅ i, y0 + y1 ⋅ i).
    /// @notice The point at infinity is encoded as (0,0,0,0) and compressed to (0,0).
    /// @param c0 The first half of the compresed point (x0 with two signal bits).
    /// @param c1 The second half of the compressed point (x1 unmodified).
    /// @return x0 The real part of the X coordinate.
    /// @return x1 The imaginary poart of the X coordinate.
    /// @return y0 The real part of the Y coordinate.
    /// @return y1 The imaginary part of the Y coordinate.
    function decompress_g2(
        uint256 c0,
        uint256 c1
    ) internal view returns (uint256 x0, uint256 x1, uint256 y0, uint256 y1) {
        // Note that X = (0, 0) is not on the curve since 0³ + 3/(9 + i) is not a square.
        // so we can use it to represent the point at infinity.
        if (c0 == 0 && c1 == 0) {
            // Point at infinity as encoded in EIP197.
            return (0, 0, 0, 0);
        }
        bool negate_point = c0 & 1 == 1;
        bool hint = c0 & 2 == 2;
        x0 = c0 >> 2;
        x1 = c1;
        if (x0 >= P || x1 >= P) {
            // G2 x0 or x1 coefficient not in field.
            revert ProofInvalid();
        }

        uint256 n3ab = mulmod(mulmod(x0, x1, P), P - 3, P);
        uint256 a_3 = mulmod(mulmod(x0, x0, P), x0, P);
        uint256 b_3 = mulmod(mulmod(x1, x1, P), x1, P);

        y0 = addmod(FRACTION_27_82_FP, addmod(a_3, mulmod(n3ab, x1, P), P), P);
        y1 = negate(
            addmod(FRACTION_3_82_FP, addmod(b_3, mulmod(n3ab, x0, P), P), P)
        );

        // Note: sqrt_Fp2 reverts if there is no solution, i.e. the point is not on the curve.
        // Note: (X³ + 3/(9 + i)) is irreducible in Fp2, so y can not be zero.
        //       But y0 or y1 may still independently be zero.
        (y0, y1) = sqrt_Fp2(y0, y1, hint);
        if (negate_point) {
            y0 = negate(y0);
            y1 = negate(y1);
        }
    }

    /// Compute the public input linear combination.
    /// @notice Reverts with PublicInputNotInField if the input is not in the field.
    /// @notice Computes the multi-scalar-multiplication of the public input
    /// elements and the verification key including the constant term.
    /// @param input The public inputs. These are elements of the scalar field Fr.
    /// @return x The X coordinate of the resulting G1 point.
    /// @return y The Y coordinate of the resulting G1 point.
    function publicInputMSM(
        uint256[24] calldata input
    ) internal view returns (uint256 x, uint256 y) {
        // Note: The ECMUL precompile does not reject unreduced values, so we check this.
        // Note: Unrolling this loop does not cost much extra in code-size, the bulk of the
        //       code-size is in the PUB_ constants.
        // ECMUL has input (x, y, scalar) and output (x', y').
        // ECADD has input (x1, y1, x2, y2) and output (x', y').
        // We reduce commitments(if any) with constants as the first point argument to ECADD.
        // We call them such that ecmul output is already in the second point
        // argument to ECADD so we can have a tight loop.
        bool success = true;
        assembly ("memory-safe") {
            let f := mload(0x40)
            let g := add(f, 0x40)
            let s
            mstore(f, CONSTANT_X)
            mstore(add(f, 0x20), CONSTANT_Y)
            mstore(g, PUB_0_X)
            mstore(add(g, 0x20), PUB_0_Y)
            s := calldataload(input)
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )
            mstore(g, PUB_1_X)
            mstore(add(g, 0x20), PUB_1_Y)
            s := calldataload(add(input, 32))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )
            mstore(g, PUB_2_X)
            mstore(add(g, 0x20), PUB_2_Y)
            s := calldataload(add(input, 64))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )
            mstore(g, PUB_3_X)
            mstore(add(g, 0x20), PUB_3_Y)
            s := calldataload(add(input, 96))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )
            mstore(g, PUB_4_X)
            mstore(add(g, 0x20), PUB_4_Y)
            s := calldataload(add(input, 128))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )
            mstore(g, PUB_5_X)
            mstore(add(g, 0x20), PUB_5_Y)
            s := calldataload(add(input, 160))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )
            mstore(g, PUB_6_X)
            mstore(add(g, 0x20), PUB_6_Y)
            s := calldataload(add(input, 192))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )
            mstore(g, PUB_7_X)
            mstore(add(g, 0x20), PUB_7_Y)
            s := calldataload(add(input, 224))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )
            mstore(g, PUB_8_X)
            mstore(add(g, 0x20), PUB_8_Y)
            s := calldataload(add(input, 256))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )
            mstore(g, PUB_9_X)
            mstore(add(g, 0x20), PUB_9_Y)
            s := calldataload(add(input, 288))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )
            mstore(g, PUB_10_X)
            mstore(add(g, 0x20), PUB_10_Y)
            s := calldataload(add(input, 320))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )
            mstore(g, PUB_11_X)
            mstore(add(g, 0x20), PUB_11_Y)
            s := calldataload(add(input, 352))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )
            mstore(g, PUB_12_X)
            mstore(add(g, 0x20), PUB_12_Y)
            s := calldataload(add(input, 384))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )
            mstore(g, PUB_13_X)
            mstore(add(g, 0x20), PUB_13_Y)
            s := calldataload(add(input, 416))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )
            mstore(g, PUB_14_X)
            mstore(add(g, 0x20), PUB_14_Y)
            s := calldataload(add(input, 448))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )
            mstore(g, PUB_15_X)
            mstore(add(g, 0x20), PUB_15_Y)
            s := calldataload(add(input, 480))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )
            mstore(g, PUB_16_X)
            mstore(add(g, 0x20), PUB_16_Y)
            s := calldataload(add(input, 512))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )
            mstore(g, PUB_17_X)
            mstore(add(g, 0x20), PUB_17_Y)
            s := calldataload(add(input, 544))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )
            mstore(g, PUB_18_X)
            mstore(add(g, 0x20), PUB_18_Y)
            s := calldataload(add(input, 576))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )
            mstore(g, PUB_19_X)
            mstore(add(g, 0x20), PUB_19_Y)
            s := calldataload(add(input, 608))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )
            mstore(g, PUB_20_X)
            mstore(add(g, 0x20), PUB_20_Y)
            s := calldataload(add(input, 640))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )
            mstore(g, PUB_21_X)
            mstore(add(g, 0x20), PUB_21_Y)
            s := calldataload(add(input, 672))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )
            mstore(g, PUB_22_X)
            mstore(add(g, 0x20), PUB_22_Y)
            s := calldataload(add(input, 704))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )
            mstore(g, PUB_23_X)
            mstore(add(g, 0x20), PUB_23_Y)
            s := calldataload(add(input, 736))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40)
            )
            success := and(
                success,
                staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            )

            x := mload(f)
            y := mload(add(f, 0x20))
        }
        if (!success) {
            // Either Public input not in field, or verification key invalid.
            // We assume the contract is correctly generated, so the verification key is valid.
            revert PublicInputNotInField();
        }
    }

    /// Compress a proof.
    /// @notice Will revert with InvalidProof if the curve points are invalid,
    /// but does not verify the proof itself.
    /// @param proof The uncompressed Groth16 proof. Elements are in the same order as for
    /// verifyProof. I.e. Groth16 points (A, B, C) encoded as in EIP-197.
    /// @return compressed The compressed proof. Elements are in the same order as for
    /// verifyCompressedProof. I.e. points (A, B, C) in compressed format.
    function compressProof(
        uint256[8] calldata proof
    ) public view returns (uint256[4] memory compressed) {
        compressed[0] = compress_g1(proof[0], proof[1]);
        (compressed[2], compressed[1]) = compress_g2(
            proof[3],
            proof[2],
            proof[5],
            proof[4]
        );
        compressed[3] = compress_g1(proof[6], proof[7]);
    }

    /// Verify a Groth16 proof with compressed points.
    /// @notice Reverts with InvalidProof if the proof is invalid or
    /// with PublicInputNotInField the public input is not reduced.
    /// @notice There is no return value. If the function does not revert, the
    /// proof was successfully verified.
    /// @param compressedProof the points (A, B, C) in compressed format
    /// matching the output of compressProof.
    /// @param input the public input field elements in the scalar field Fr.
    /// Elements must be reduced.
    function verifyCompressedProof(
        uint256[4] calldata compressedProof,
        uint256[24] calldata input
    ) public view {
        uint256[24] memory pairings;

        {
            (uint256 Ax, uint256 Ay) = decompress_g1(compressedProof[0]);
            (
                uint256 Bx0,
                uint256 Bx1,
                uint256 By0,
                uint256 By1
            ) = decompress_g2(compressedProof[2], compressedProof[1]);
            (uint256 Cx, uint256 Cy) = decompress_g1(compressedProof[3]);
            (uint256 Lx, uint256 Ly) = publicInputMSM(input);

            // Verify the pairing
            // Note: The precompile expects the F2 coefficients in big-endian order.
            // Note: The pairing precompile rejects unreduced values, so we won't check that here.
            // e(A, B)
            pairings[0] = Ax;
            pairings[1] = Ay;
            pairings[2] = Bx1;
            pairings[3] = Bx0;
            pairings[4] = By1;
            pairings[5] = By0;
            // e(C, -δ)
            pairings[6] = Cx;
            pairings[7] = Cy;
            pairings[8] = DELTA_NEG_X_1;
            pairings[9] = DELTA_NEG_X_0;
            pairings[10] = DELTA_NEG_Y_1;
            pairings[11] = DELTA_NEG_Y_0;
            // e(α, -β)
            pairings[12] = ALPHA_X;
            pairings[13] = ALPHA_Y;
            pairings[14] = BETA_NEG_X_1;
            pairings[15] = BETA_NEG_X_0;
            pairings[16] = BETA_NEG_Y_1;
            pairings[17] = BETA_NEG_Y_0;
            // e(L_pub, -γ)
            pairings[18] = Lx;
            pairings[19] = Ly;
            pairings[20] = GAMMA_NEG_X_1;
            pairings[21] = GAMMA_NEG_X_0;
            pairings[22] = GAMMA_NEG_Y_1;
            pairings[23] = GAMMA_NEG_Y_0;

            // Check pairing equation.
            bool success;
            uint256[1] memory output;
            assembly ("memory-safe") {
                success := staticcall(
                    gas(),
                    PRECOMPILE_VERIFY,
                    pairings,
                    0x300,
                    output,
                    0x20
                )
            }
            if (!success || output[0] != 1) {
                // Either proof or verification key invalid.
                // We assume the contract is correctly generated, so the verification key is valid.
                revert ProofInvalid();
            }
        }
    }

    /// Verify an uncompressed Groth16 proof.
    /// @notice Reverts with InvalidProof if the proof is invalid or
    /// with PublicInputNotInField the public input is not reduced.
    /// @notice There is no return value. If the function does not revert, the
    /// proof was successfully verified.
    /// @param proof the points (A, B, C) in EIP-197 format matching the output
    /// of compressProof.
    /// @param input the public input field elements in the scalar field Fr.
    /// Elements must be reduced.
    function verifyProof(
        uint256[8] calldata proof,
        uint256[24] calldata input
    ) public view {
        (uint256 x, uint256 y) = publicInputMSM(input);

        // Note: The precompile expects the F2 coefficients in big-endian order.
        // Note: The pairing precompile rejects unreduced values, so we won't check that here.
        bool success;
        assembly ("memory-safe") {
            let f := mload(0x40) // Free memory pointer.

            // Copy points (A, B, C) to memory. They are already in correct encoding.
            // This is pairing e(A, B) and G1 of e(C, -δ).
            calldatacopy(f, proof, 0x100)

            // Complete e(C, -δ) and write e(α, -β), e(L_pub, -γ) to memory.
            // OPT: This could be better done using a single codecopy, but
            //      Solidity (unlike standalone Yul) doesn't provide a way to
            //      to do this.
            mstore(add(f, 0x100), DELTA_NEG_X_1)
            mstore(add(f, 0x120), DELTA_NEG_X_0)
            mstore(add(f, 0x140), DELTA_NEG_Y_1)
            mstore(add(f, 0x160), DELTA_NEG_Y_0)
            mstore(add(f, 0x180), ALPHA_X)
            mstore(add(f, 0x1a0), ALPHA_Y)
            mstore(add(f, 0x1c0), BETA_NEG_X_1)
            mstore(add(f, 0x1e0), BETA_NEG_X_0)
            mstore(add(f, 0x200), BETA_NEG_Y_1)
            mstore(add(f, 0x220), BETA_NEG_Y_0)
            mstore(add(f, 0x240), x)
            mstore(add(f, 0x260), y)
            mstore(add(f, 0x280), GAMMA_NEG_X_1)
            mstore(add(f, 0x2a0), GAMMA_NEG_X_0)
            mstore(add(f, 0x2c0), GAMMA_NEG_Y_1)
            mstore(add(f, 0x2e0), GAMMA_NEG_Y_0)

            // Check pairing equation.
            success := staticcall(gas(), PRECOMPILE_VERIFY, f, 0x300, f, 0x20)
            // Also check returned value (both are either 1 or 0).
            success := and(success, mload(f))
        }
        if (!success) {
            // Either proof or verification key invalid.
            // We assume the contract is correctly generated, so the verification key is valid.
            revert ProofInvalid();
        }
    }
}
