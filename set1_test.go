package cryptopals

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

func TestChallenge1(t *testing.T) {
	res, err := hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	if err != nil {
		t.Fatal(err)
	}
	if res != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
		t.Error("Failed in challenge 1", res)
	}
}

func TestChallenge2(t *testing.T) {
	a, err := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	if err != nil {
		t.Fatal(err)
	}

	b, err := hex.DecodeString("686974207468652062756c6c277320657965")
	if err != nil {
		t.Fatal(err)
	}

	c := fixedXOR(a, b)
	if hex.EncodeToString(c) != "746865206b696420646f6e277420706c6179" {
		t.Error("Failed in challenge 2")
	}
}

func corpusFromFile(name string) map[rune]float64 {
	text, err := ioutil.ReadFile(name)
	if err != nil {
		panic(fmt.Sprintln("Failed to open corpus file: ", err))
	}
	return buildCorpus(string(text))
}

var corpus = corpusFromFile("_set1_data/pride_and_prejudice.txt")

func TestChallenge3(t *testing.T) {
	message, err := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	if err != nil {
		t.Fatal("Failed to decode string: ", err)
	}

	key, res, _ := findSingleByteXOR(message, corpus)
	t.Logf("key = %c, message = %s", key, res)
}

func TestChallenge4(t *testing.T) {
	f, err := os.Open("_set1_data/4.txt")
	if err != nil {
		t.Fatal("Failed to read file: ", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	var bestScore float64
	var res []byte
	var key byte
	for scanner.Scan() {
		message, err := hex.DecodeString(scanner.Text())
		if err != nil {
			t.Fatal("Failed to decode string: ", err)
		}

		k, out, score := findSingleByteXOR(message, corpus)
		if score > bestScore {
			bestScore = score
			res = out
			key = k
		}
	}

	t.Logf("key = %c, message = %s", key, res)
}

func TestChallenge5(t *testing.T) {
	message, err := hex.DecodeString("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
	if err != nil {
		t.Fatal("Failed to decode string: ", err)
	}

	out := repeatingXOR([]byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"), []byte("ICE"))

	if !bytes.Equal(message, out) {
		t.Error("Failed in challenge 5")
	}
}

func TestChallenge6(t *testing.T) {
	if 37 != hammingDistance([]byte("this is a test"), []byte("wokka wokka!!!")) {
		t.Error("Failed in challenge 6")
	}

	text, err := ioutil.ReadFile("_set1_data/6.txt")
	if err != nil {
		panic(fmt.Sprintln("Failed to open file: ", err))
	}

	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		panic("Failed to base64 decode text")
	}

	t.Logf("key size = %d", findRepeatingXORKeySize(data))

	key := findRepeatingXORKey(data, corpus)
	t.Logf("key = %s", string(key))

	t.Logf("%s", string(repeatingXOR(data, key)))
}

func TestChallenge7(t *testing.T) {
	text, err := ioutil.ReadFile("_set1_data/7.txt")
	if err != nil {
		panic(fmt.Sprintln("Failed to open corpus file: ", err))
	}

	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		panic("Failed to base64 decode text")
	}

	c, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	if err != nil {
		t.Fatal("Failed to new aes cipher: ", err)
	}

	out := decryptECB(data, c)
	t.Logf("%s", out)
}

func TestChallenge8(t *testing.T) {
	f, err := os.Open("_set1_data/8.txt")
	if err != nil {
		t.Fatal("Failed to read file: ", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	n := 1
	for scanner.Scan() {
		data, err := base64.StdEncoding.DecodeString(scanner.Text())
		if err != nil {
			panic("Failed to base64 decode text")
		}

		if detectECB(data, 16) {
			t.Logf("Number %d ciphertext is encrypted with ECB", n)
		}

		n++
	}
}
