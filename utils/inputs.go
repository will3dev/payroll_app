package utils

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	babyjub "github.com/iden3/go-iden3-crypto/babyjub"
)

func ECEG_Encrypt(pk *babyjub.PublicKey, value *big.Int) (c1 *babyjub.Point, c2 *babyjub.Point, r *big.Int) {
	r, _ = rand.Int(rand.Reader, babyjub.Order)
	c1 = babyjub.B8.Mul(r, babyjub.B8)
	t1 := babyjub.B8.Mul(r, pk.Point()).Projective()
	t2 := babyjub.B8.Mul(value, babyjub.B8).Projective()
	c2 = t1.Add(t1, t2).Affine()
	return c1, c2, r
}

func ECEG_Decrypt(sk *babyjub.PrivKeyScalar, c1 *babyjub.Point, c2 *babyjub.Point) *babyjub.Point {
	negSk := new(big.Int).Sub(babyjub.Order, sk.BigInt())
	t1 := c1.Mul(negSk, c1).Projective()
	t2 := t1.Add(t1, c2.Projective()).Affine()
	return t2
}

func Neg(x *big.Int) *big.Int {
	return new(big.Int).Sub(babyjub.Order, x)
}

func ECDH_PoseidonEncrypt(pk *babyjub.PublicKey, value *big.Int) ([]*big.Int, *big.Int, *babyjub.Point, *babyjub.Point, error) {
	r, _ := rand.Int(rand.Reader, babyjub.Order)
	pkr := babyjub.B8.Mul(r, pk.Point())
	br := babyjub.B8.Mul(r, babyjub.B8)

	key := []*big.Int{pkr.X, pkr.Y}
	nonce, _ := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(100), nil))
	msg := []*big.Int{value, big.NewInt(0)}
	cipherText, err := PoseidonEncrypt(msg, key, nonce)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("Error at Poseidon encryption: %w", err)
	}
	return cipherText, nonce, pkr, br, nil
}

func TestPoseidonDecrypt(t *testing.T) {
	x, _ := new(big.Int).SetString("2225468530552752510522780019536893048169408270351832766087923920964657502364", 10)
	y, _ := new(big.Int).SetString("18264896395019517559018400396898398442219687903646821466907778802937824776999", 10)
	key := []*big.Int{x, y}
	nonce, _ := new(big.Int).SetString("220373351579243596212522709113509916796", 10)
	c1, _ := new(big.Int).SetString("3623473636383738070031324804097049685564466189577273141109672613904615191520", 10)
	c2, _ := new(big.Int).SetString("14192366070411288656840625597415252300006763456323771445497376523077328650161", 10)
	c3, _ := new(big.Int).SetString("8948874854696341437962075211230225158124203775185169948359228967178039019393", 10)
	c4, _ := new(big.Int).SetString("13654519867376896827561074824557193869787926453227340059166840999629617764240", 10)
	cipherText := []*big.Int{c1, c2, c3, c4}
	msg, _ := PoseidonDecrypt(cipherText, key, nonce, 2)
	fmt.Println(msg[0].Text(10))
	fmt.Println(msg[1].Text(10))
}

func GenerateTransferInputs() {
	skpSender := babyjub.NewRandPrivKey()
	skSender := skpSender.Scalar()
	pkSender := skpSender.Public()

	skpReceiver := babyjub.NewRandPrivKey()
	skReceiver := skpReceiver.Scalar()
	pkReceiver := skpReceiver.Public()
	fmt.Println("Private key sender:", skSender.BigInt())
	fmt.Println("Public key sender:", pkSender.X.String(), pkSender.Y.String())

	fmt.Println("Private key receiver:", skReceiver.BigInt())
	fmt.Println("Public key receiver:", pkReceiver.X.String(), pkReceiver.Y.String())

	balance, _ := rand.Int(rand.Reader, big.NewInt(0).Exp(big.NewInt(2), big.NewInt(160), nil))
	fmt.Println("Balance:", balance)
	c1Balance, c2Balance, _ := ECEG_Encrypt(pkSender, balance)

	value, _ := rand.Int(rand.Reader, balance)
	fmt.Println("Value:", value)
	c1ValueSender, c2ValueSender, _ := ECEG_Encrypt(pkSender, Neg(value)) // sender's value is negative

	c1ValueReceiver, c2ValueReceiver, recvRandom := ECEG_Encrypt(pkReceiver, value) // receiver's value is positive

	senderPCT, senderNonce, senderAuthKey, senderBr, err := ECDH_PoseidonEncrypt(pkSender, value)
	if err != nil {
		fmt.Println("Error at ECDH_PoseidonEncrypt:", err)
	}

}
