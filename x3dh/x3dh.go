package x3dh

import (
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
	"math/big"
)

var (
	p = big.NewInt(37)
	g = big.NewInt(2)
)

func intToBytes(x *big.Int) []byte {
	b := x.Bytes()
	if len(b) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(b):], b)
		return padded
	}
	return b
}

func HKDF(dhValues ...*big.Int) []byte {
	var combined []byte
	for _, dh := range dhValues {
		combined = append(combined, intToBytes(dh)...)
	}

	hash := sha256.New
	salt := []byte("X3DH-salt")
	info := []byte("X3DH-info")
	hkdf := hkdf.New(hash, combined, salt, info)

	sharedSecret := make([]byte, 32)
	_, err := io.ReadFull(hkdf, sharedSecret)
	if err != nil {
		panic(err)
	}

	return sharedSecret
}

type Server struct {
	IK_Rec  *big.Int
	IK_Send *big.Int
	EK      *big.Int
	SPK     *big.Int
	OPK     *big.Int
}

type Receiver struct {
	ik  *big.Int // Private Identity Key
	spk *big.Int // Private Signed Pre-Key
	opk *big.Int // Private One-time Pre-Key
	IK  *big.Int // Public Identity Key
	SPK *big.Int // Public Signed Pre-Key
	OPK *big.Int // One-time Pre-Key

	DH []*big.Int
}

type Sender struct {
	ik *big.Int // Private Identity Key
	ek *big.Int // Private Ephemeral Key
	IK *big.Int // Identity Key
	EK *big.Int // Ephemeral Key

	DH []*big.Int
}

func (rec *Receiver) InitReceiver(ik, spk, opk int64) {
	rec.ik = big.NewInt(ik)
	rec.spk = big.NewInt(spk)
	rec.opk = big.NewInt(opk)

	rec.IK = new(big.Int).Exp(g, rec.ik, p)
	rec.SPK = new(big.Int).Exp(g, rec.spk, p)
	rec.OPK = new(big.Int).Exp(g, rec.opk, p)

	rec.DH = make([]*big.Int, 4)
}

func (send *Sender) InitSender(ik, ek int64) {
	send.ik = big.NewInt(ik)
	send.ek = big.NewInt(ek)

	send.IK = new(big.Int).Exp(g, send.ik, p)
	send.EK = new(big.Int).Exp(g, send.ek, p)

	send.DH = make([]*big.Int, 4)
}

func (srv *Server) InitServer(rec *Receiver, send *Sender) {
	srv.IK_Rec = rec.IK
	srv.SPK = rec.SPK
	srv.OPK = rec.OPK
	srv.IK_Send = send.IK
	srv.EK = send.EK
}

func (send *Sender) ComputeDH(server *Server) {
	send.DH[0] = new(big.Int).Exp(server.SPK, send.ik, p)
	send.DH[1] = new(big.Int).Exp(server.IK_Rec, send.ek, p)
	send.DH[2] = new(big.Int).Exp(server.SPK, send.ek, p)
	send.DH[3] = new(big.Int).Exp(server.OPK, send.ek, p)
}

func (rec *Receiver) ComputeDH(server *Server) {
	rec.DH[0] = new(big.Int).Exp(server.IK_Send, rec.spk, p)
	rec.DH[1] = new(big.Int).Exp(server.EK, rec.ik, p)
	rec.DH[2] = new(big.Int).Exp(server.EK, rec.spk, p)
	rec.DH[3] = new(big.Int).Exp(server.EK, rec.opk, p)
}

func main() {
	bob := &Receiver{}
	bob.InitReceiver(5, 7, 11)

	alice := &Sender{}
	alice.InitSender(3, 13)

	server := &Server{}
	server.InitServer(bob, alice)

	fmt.Println("\nPublic Values:")
	fmt.Println("Alice's Ephemeral Public Key:", server.EK)
	fmt.Println("Alice's Identity Public Key:  ", server.IK_Send)
	fmt.Println("Bob's Identity Public Key:    ", server.IK_Rec)
	fmt.Println("Bob's Signed Pre-Key:        ", server.SPK)
	fmt.Println("Bob's One-Time Pre-Key:      ", server.OPK)

	alice.ComputeDH(server)
	fmt.Println("\nAlice DH Results:")
	fmt.Println("DH1 (IK_A, SPK_B):", alice.DH[0])
	fmt.Println("DH2 (EK_A, IK_B): ", alice.DH[1])
	fmt.Println("DH3 (EK_A, SPK_B):", alice.DH[2])
	fmt.Println("DH4 (EK_A, OPK_B):", alice.DH[3])

	aliceSecret := HKDF(alice.DH...)
	fmt.Println("\nAlice Secret:", aliceSecret)

	bob.ComputeDH(server)
	fmt.Println("\nBob's DH Results:")
	fmt.Println("DH1 (SPK_B, IK_A):", bob.DH[0])
	fmt.Println("DH2 (IK_B, EK_A): ", bob.DH[1])
	fmt.Println("DH3 (SPK_B, EK_A):", bob.DH[2])
	fmt.Println("DH4 (OPK_B, EK_A):", bob.DH[3])

	bobSecret := HKDF(bob.DH...)
	fmt.Println("\nBob Secret:", bobSecret)
}
