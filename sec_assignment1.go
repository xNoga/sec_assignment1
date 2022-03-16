package main

import (
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

var (
	prime     = big.NewInt(6661)
	gen       = big.NewInt(666)
	bobPubKey = big.NewInt(2227)
	msg       = big.NewInt(2000)
)

func main() {
	// generate random
	rand.Seed(time.Now().UnixNano())
	randomKVal := big.NewInt(rand.Int63n(1000))
	fmt.Printf("\nThe random k generated is: %v\n\n", randomKVal)

	// Part 1
	a, b := customEncrypt(bobPubKey, randomKVal, prime, gen, msg)

	// Alice sends the encrypted message
	sendMessage("Alice", a, b)

	// Part 2
	fmt.Printf("Eve is listening on the network and sees the values. Eve tries to brute force Bob's private key\nwith public key value 2227\n\n")

	bobPriK := bruteForcePrivateKey(bobPubKey, gen, prime)
	fmt.Printf("Bob's private key is: %v\n\n", bobPriK)

	msgFromAlice := customDecrypt(a, b, bobPriK, prime)
	fmt.Printf("The message that was sent from Alice was: %v\n\n", msgFromAlice)

	fmt.Printf("Eve also tries to brute force random value k used in Alice's message\nso she can reconstruct the message with the original a and b values\n\n")

	randomK := bruteForceRandomK(a, bobPubKey, prime, gen)
	fmt.Printf("The random k: %v\n\n", randomK)

	a2, b2 := customEncrypt(bobPubKey, randomK, prime, gen, msgFromAlice)
	sendMessage("Eve", a2, b2)

	// Part 3

	// Mallory would need to run bruteForceRandomK also, but we already did that, so we just use the value here
	fmt.Printf("Mallory intercepts the message from Alice to Bob. Se modifies the message to '6000'\n\n")
	fmt.Println("Mallory brute forces the random value k so she can generate new b value\n")
	_, _b := customEncrypt(bobPubKey, randomK, prime, gen, big.NewInt(int64(6000)))
	sendMessage("Mallory", a, _b)

	msgFromMallory := customDecrypt(a, _b, bobPriK, prime)
	fmt.Printf("The modified msg to Bob is: %v\n\n", msgFromMallory)
}

func customEncrypt(pubK, k, p, g, m *big.Int) (a, b *big.Int) {
	a = new(big.Int).Exp(g, k, p)
	b = new(big.Int).Exp(pubK, k, nil)
	b.Mul(b, m)
	b.Mod(b, p)
	return
}

func customDecrypt(a, b, priK, p *big.Int) *big.Int {
	msg := new(big.Int).Exp(a, priK, p)
	msg.ModInverse(msg, p) // get the multiplicative inverse
	msg.Mul(msg, b)
	msg.Mod(msg, p)

	return msg
}

func bruteForcePrivateKey(pubK, gen, prime *big.Int) *big.Int {
	x := int64(1)
	for true {
		pk := generatePublibKey(gen, big.NewInt(x), prime)
		if pk.Cmp(pubK) == 0 { // Cmp = '=='
			break
		}
		x++
	}
	return big.NewInt(x)
}

func bruteForceRandomK(a, pubK, prime, gen *big.Int) *big.Int {
	k := int64(1)
	for true {
		_a := new(big.Int).Exp(gen, big.NewInt(k), prime)
		if a.Cmp(_a) == 0 { // Cmp = compare = '=='
			break
		}
		k++
	}
	return big.NewInt(k)
}

func generatePublibKey(gen, k, prime *big.Int) *big.Int {
	return new(big.Int).Exp(gen, k, prime)
}

// does nothing - just for flow purposes in main func
func sendMessage(name string, a, b *big.Int) {
	fmt.Printf("%s is sending a: %v and b: %v over the network\n\n", name, a, b)
}
