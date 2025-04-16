package main

import (
	"time"

	dr "github.com/TypicalAM/signal-toy/double-ratchet"
	x3dh "github.com/TypicalAM/signal-toy/x3dh"
	"github.com/charmbracelet/log"
)

func main() {
	log.SetLevel(log.DebugLevel)

	receiver := x3dh.Receiver{}
	receiver.InitReceiver(3, 5, 7)

	sender := x3dh.Sender{}
	sender.InitSender(11, 13)

	server := x3dh.Server{}
	server.InitServer(&receiver, &sender)

	sender.ComputeDH(&server)
	rkSender := x3dh.HKDF(sender.DH...)

	alice, err := dr.NewRatchet(rkSender)
	if err != nil {
		log.Fatal("Failed to create alice", "err", err)
	}

	receiver.ComputeDH(&server)
	rkReceiver := x3dh.HKDF(receiver.DH...)
	bob, err := dr.NewRatchet(rkReceiver)
	if err != nil {
		log.Fatal("Failed to create bob", "err", err)
	}

	alice.InitPeer(bob.DHsPub[:])
	bob.InitPeer(alice.DHsPub[:])

	aliceToBob := make(Queue, 10)
	bobToAlice := make(Queue, 10)
	aliceUser := &User{"Alice", alice, bobToAlice, aliceToBob}
	bobUser := &User{"Bob", bob, aliceToBob, bobToAlice}
	aliceUser.Start()
	bobUser.Start()

	// Chat
	log.Info("Starting secure conversation")
	aliceUser.Send("Hello Bob!")
	time.Sleep(100 * time.Millisecond)

	bobUser.Send("Hey Alice!")
	time.Sleep(100 * time.Millisecond)

	aliceUser.Send("How are you?")
	time.Sleep(100 * time.Millisecond)

	bobUser.Send("Good, and you?")
	time.Sleep(100 * time.Millisecond)
	bobUser.Send("Hello? Are you there?")
	time.Sleep(100 * time.Millisecond)
	bobUser.Send("Did you skip any messages?")
	time.Sleep(100 * time.Millisecond)

	aliceUser.Send("I don't think so but if I did I would have handled them gracefully!")
	time.Sleep(50 * time.Millisecond)

	bobUser.Send("Bread")
	time.Sleep(50 * time.Millisecond)
	log.Info("Secure conversation ended!")
}
