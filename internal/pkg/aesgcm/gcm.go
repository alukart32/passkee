// The aesgcm package provides a data encryptor based on the AES-GCM algorithm.
package aesgcm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"runtime"

	"golang.org/x/sync/errgroup"
)

const (
	// blockSize is the default length of cipher block in bytes.
	blockSize = 4096

	// keySize is the AES-256 key size in bytes.
	keySize = 32

	// nonceSize is the default length of AES iv in bytes.
	nonceSize = 12

	// authTagSize is the default length of AD in bytes.
	authTagSize = 16

	// overhead sets the maximum possible overflow in a single block.
	overhead = nonceSize + authTagSize
)

// encrypter is used to encipher and decipher content.
type encrypter struct {
	// GCM. This is used for content encryption.
	aead cipher.AEAD
}

// Encrypter returns an initialized Encrypter instance.
func Encrypter(key []byte) (*encrypter, error) {
	if len(key) < keySize {
		return nil, fmt.Errorf("unexpected key size %v", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aeadCipher, err := cipher.NewGCMWithNonceSize(block, nonceSize)
	if err != nil {
		return nil, err
	}

	return &encrypter{
		aead: aeadCipher,
	}, nil
}

// Decrypt verifies and decrypts ciphertext.
func (e *encrypter) Decrypt(ciphertext []byte) ([]byte, error) {
	return e.doDecryptBlock(ciphertext, uint64(1))
}

// DecryptBlock verifies and decrypts ciphertext as a separate block.
func (e *encrypter) DecryptBlock(ciphertext []byte, blockNo uint64) ([]byte, error) {
	return e.doDecryptBlock(ciphertext, blockNo)
}

// DecryptBlocks verifies and decrypts ciphertext as sequential blocks.
func (e *encrypter) DecryptBlocks(ciphertext []byte) ([]byte, error) {
	var err error

	cBuf := bytes.NewBuffer(ciphertext)

	blockNo := uint64(1)
	plaintext := make([][]byte, 1+(len(ciphertext)-1)/blockSize)
	for cBuf.Len() > 0 {
		ciphertext := cBuf.Next(int(blockSize))

		var block []byte
		block, err = e.doDecryptBlock(ciphertext, blockNo)
		if err != nil {
			break
		}
		plaintext = append(plaintext, block)
		blockNo++
	}
	out := new(bytes.Buffer)
	for _, b := range plaintext {
		_, err := out.Write(b)
		if err != nil {
			return nil, err
		}
	}

	return out.Bytes(), err
}

// doDecryptBlock performs block decryption.
// blockNo is used as associated data.
func (e *encrypter) doDecryptBlock(ciphertext []byte, blockNo uint64) ([]byte, error) {
	if len(ciphertext) == 0 {
		return ciphertext, fmt.Errorf("empty ciphertext")
	}
	if len(ciphertext) < nonceSize {
		log.Panic("block is too short")
	}

	// Extract nonce
	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	// Decrypt
	ad := blockAD(blockNo)
	plaintext := make([]byte, blockSize)
	plaintext, err := e.aead.Open(plaintext[:0], nonce, ciphertext, ad)
	if err != nil {
		log.Panic(err)
	}

	return plaintext, nil
}

// Encrypt encrypts plaintext.
func (e *encrypter) Encrypt(plaintext []byte) ([]byte, error) {
	return e.doEncryptBlock(plaintext, uint64(1))
}

// EncryptBlock encrypts plaintext as a separete cpihertext block.
func (e *encrypter) EncryptBlock(plaintext []byte, blockNo uint64) ([]byte, error) {
	return e.doEncryptBlock(plaintext, blockNo)
}

// doEncryptBlock performs block encryption.
// blockNo is used as associated data.
// The output is nonce + ciphertext + tag.
func (e *encrypter) doEncryptBlock(plaintext []byte, blockNo uint64) ([]byte, error) {
	if len(plaintext) == 0 {
		return plaintext, fmt.Errorf("empty plaintext")
	}
	nonce, err := randomNonce(nonceSize)
	if err != nil {
		log.Panic(err)
	}

	// Block is authenticated with block number.
	ad := blockAD(blockNo)
	block := make([]byte, e.aead.NonceSize())
	copy(block, nonce)
	block = block[0:len(nonce)]
	// Encrypt plaintext and append to nonce.
	ciphertext := e.aead.Seal(block, nonce, plaintext, ad)
	if len(plaintext)+overhead != len(ciphertext) {
		log.Panicf("unexpected ciphertext length: plaintext=%d, overhead=%d, ciphertext=%d",
			len(plaintext), overhead, len(ciphertext))
	}
	return ciphertext, nil
}

// EncryptBlocks encrypts plaintext that contains multiple blocks.
func (e *encrypter) EncryptBlocks(plaintextBlocks [][]byte) ([]byte, error) {
	firstBlockNo := uint64(1)
	ciphertextBlocks := make([][]byte, len(plaintextBlocks))
	// For large writes, we parallelize encryption.
	if len(plaintextBlocks) >= 32 {
		ncpu := runtime.NumCPU()
		if ncpu > 2 {
			ncpu = 2
		}
		groups := len(plaintextBlocks) / ncpu

		grp := new(errgroup.Group)
		for i := 0; i < ncpu; i++ {
			n := i
			grp.Go(func() error {
				low := n * groups
				high := (n + 1) * groups
				if n == ncpu-1 {
					// Pick up any left-over blocks
					high = len(plaintextBlocks)
				}
				return e.doEncryptBlocks(plaintextBlocks[low:high],
					ciphertextBlocks[low:high], firstBlockNo+uint64(low))
			})
		}
		if err := grp.Wait(); err != nil {
			return nil, err
		}
	} else {
		if err := e.doEncryptBlocks(plaintextBlocks, ciphertextBlocks, firstBlockNo); err != nil {
			return nil, err
		}
	}
	out := new(bytes.Buffer)
	for _, b := range ciphertextBlocks {
		_, err := out.Write(b)
		if err != nil {
			return nil, err
		}
	}

	return out.Bytes(), nil
}

// doEncryptBlocks performs block encryption.
func (e *encrypter) doEncryptBlocks(in [][]byte, out [][]byte, firstBlockNo uint64) error {
	var err error
	for i, v := range in {
		out[i], err = e.doEncryptBlock(v, firstBlockNo+uint64(i))
		if err != nil {
			return err
		}
	}
	return nil
}

// blockAD returns the block number as associated data (AD).
func blockAD(blockNo uint64) (aData []byte) {
	aData = make([]byte, 8)
	binary.BigEndian.PutUint64(aData, blockNo)
	return aData
}

// randomNonce generates random bytes.
func randomNonce(size int) ([]byte, error) {
	if size == 0 {
		return nil, fmt.Errorf("zero size")
	}
	if size != nonceSize {
		return nil, fmt.Errorf("wrong nonce length")
	}

	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
