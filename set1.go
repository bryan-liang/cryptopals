package cryptopals

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"log"
	"math"
	"math/bits"
	"unicode/utf8"
)

func hexToBase64(hs string) (string, error) {
	v, err := hex.DecodeString(hs)
	if err != nil {
		return "", err
	}
	log.Printf("%s", v)

	return base64.StdEncoding.EncodeToString(v), nil
}

func fixedXOR(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("FixedXOR: mismatched lengths")
	}

	res := make([]byte, len(a))
	for i := range a {
		res[i] = a[i] ^ b[i]
	}

	return res
}

func buildCorpus(text string) map[rune]float64 {
	corpus := make(map[rune]float64)

	for _, char := range text {
		corpus[char]++
	}

	total := utf8.RuneCountInString(text)
	for k, v := range corpus {
		corpus[k] = v / float64(total)
	}

	return corpus
}

func scoreEnglish(text string, corpus map[rune]float64) float64 {
	var score float64
	for _, char := range text {
		score += corpus[char]
	}
	return score / float64(utf8.RuneCountInString(text))
}

func singleXOR(in []byte, key byte) []byte {
	res := make([]byte, len(in))
	for i, c := range in {
		res[i] = c ^ key
	}
	return res
}

func findSingleByteXOR(in []byte, corpus map[rune]float64) (byte, []byte, float64) {
	var res []byte
	var bestScore float64
	var key byte

	for k := 0; k < 256; k++ {
		out := singleXOR(in, byte(k))
		score := scoreEnglish(string(out), corpus)
		if score > bestScore {
			res = out
			bestScore = score
			key = byte(k)
		}
	}
	return key, res, bestScore
}

func repeatingXOR(in, key []byte) []byte {
	res := make([]byte, len(in))
	n := 0

	for i, c := range in {
		res[i] = c ^ key[n]
		n++
		if n >= len(key) {
			n = 0
		}
	}

	return res
}

func hammingDistance(a, b []byte) int {
	if len(a) != len(b) {
		panic("different lengths")
	}

	var res int
	for i := range a {
		res += bits.OnesCount8(a[i] ^ b[i])
	}
	return res
}

func findRepeatingXORKeySize(in []byte) int {
	var res int
	bestScore := math.MaxFloat64
	for keyLen := 2; keyLen <= 40; keyLen++ {
		a, b := in[:keyLen*4], in[keyLen*4:keyLen*4*2]
		score := float64(hammingDistance(a, b)) / float64(keyLen)
		if score < bestScore {
			bestScore = score
			res = keyLen
		}
	}
	return res
}

func findRepeatingXORKey(in []byte, corpus map[rune]float64) []byte {
	keySize := findRepeatingXORKeySize(in)
	key := make([]byte, keySize)
	nRow := (len(in) + keySize - 1) / keySize

	for col := 0; col < keySize; col++ {
		var block []byte
		if (nRow-1)*keySize+col >= len(in) {
			block = make([]byte, nRow-1)
		} else {
			block = make([]byte, nRow)
		}

		for row := 0; row < nRow; row++ {
			if row*keySize+col >= len(in) {
				continue
			}
			block[row] = in[row*keySize+col]
		}
		key[col], _, _ = findSingleByteXOR(block, corpus)
	}

	return key
}

func decryptECB(in []byte, b cipher.Block) []byte {
	if len(in)%b.BlockSize() != 0 {
		panic("can't ECB decrypt")
	}

	out := make([]byte, len(in))
	for i := 0; i < len(in); i += b.BlockSize() {
		b.Decrypt(out[i:], in[i:])
	}
	return out
}

func detectECB(in []byte, blockSize int) bool {
	if len(in)%blockSize != 0 {
		panic("can't detectECB")
	}
	seen := make(map[string]struct{})
	for i := 0; i < len(in); i += blockSize {
		val := string(in[i : i+blockSize])
		if _, ok := seen[val]; ok {
			return true
		}
		seen[val] = struct{}{}
	}
	return false
}
