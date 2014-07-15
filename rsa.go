// vim: tabstop=2 shiftwidth=2

package main

import (
	"bufio"
	"encoding/binary"
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/sha256"
	"encoding/pem"
	"encoding/base64"
	"os"
	"io/ioutil"
	"strconv"
	"fmt"
	"math/big"
)

func rsa_keygen(keylen int) {
	// priv *rsa.PrivateKey;
	// err error;
	priv, err := rsa.GenerateKey(rand.Reader, keylen)
	if err != nil {
		fmt.Println(err)
		return
	}
	err = priv.Validate()
	if err != nil {
		fmt.Println("Validation failed.", err)
	}
	if priv.D.Cmp(priv.N) > 0 {
		fmt.Println("Private exponent is too large")
	}

	// Get der format. priv_der []byte
	priv_der := x509.MarshalPKCS1PrivateKey(priv)

	// pem.Block
	// blk pem.Block
	priv_blk := pem.Block {
		Type: "RSA PRIVATE KEY",
		Headers: nil,
		Bytes: priv_der,
	}

	// Resultant private key in PEM format.
	// priv_pem string
	//priv_pem = string(pem.EncodeToMemory(&priv_blk))
	fhpriv, err := os.Create("private.pem")
	defer fhpriv.Close()
	err = pem.Encode(fhpriv, &priv_blk)

	// Public Key generation
	pub := priv.PublicKey
	pub_der, err := x509.MarshalPKIXPublicKey(&pub)
	if err != nil {
		fmt.Println("Failed to get der format for PublicKey.", err)
		return;
	}

	pub_blk := pem.Block {
		Type: "PUBLIC KEY",
		Headers: nil,
		Bytes: pub_der,
	}
	//pub_pem = string(pem.EncodeToMemory(&pub_blk));
	fhpub, err := os.Create("public.pem")
	defer fhpub.Close()
	err = pem.Encode(fhpub, &pub_blk)
}

func privImport(filename string) (priv *rsa.PrivateKey) {
	pemData, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("Unable to import", filename)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		fmt.Println("File does not contain valid PEM data")
	}
	priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Printf("Bad private key: %s\n", err)
	}
	return
}

func pubImport(filename string) (rsaPub *rsa.PublicKey) {
	pemData, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("Unable to import", filename)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		fmt.Println("File does not contain valid PEM data")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Println(err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		fmt.Println("Value returned from PKIX import was not an RSA Public Key")
	}
	return
}

// mix_import_pk takes a filename (usually pubring.mix) and a keyid.  It
// returns the key as an rsa.PublicKey.
func mix_import_pk(filename, keyid string) (pk rsa.PublicKey) {
	var err error
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	scanner := bufio.NewScanner(f)
	var line string //Each line within pubring.mix
	var key_length int //Length of keyblock
	var keyblock string //content of the requested keyblock
	in_keyblock := false //True while inside a keyblock
	in_requested_keyblock := false //True while inside the required keyblock
	got_key_length := false
	for scanner.Scan() {
		line = scanner.Text()
		if line == "-----Begin Mix Key-----" {
			// Inside a keyblock
			in_keyblock = true
		} else if line == "-----End Mix Key-----" {
			// Outside a keyblock
			in_keyblock = false
			in_requested_keyblock = false
		} else if in_keyblock && line == keyid {
			// Inside the requested keyblock
			in_requested_keyblock = true
		} else if in_requested_keyblock && ! got_key_length {
			// First line in keyblock is the length identifer
			key_length, err = strconv.Atoi(line)
			if err != nil {
				panic(err)
			}
			got_key_length = true
		} else if in_requested_keyblock && got_key_length {
			// Inside requested keyblock and building key itself
			keyblock += line
		}
	}
	f.Close()
	data, err := base64.StdEncoding.DecodeString(keyblock)
	if err != nil {
		panic(err)
	}
	if len(data) != key_length {
		panic("Incorrect key length")
	}
	keylen := binary.LittleEndian.Uint16(data[0:2])
	// Cut between N and E: (1024 / 8) + 2 = 130
	midpoint := (keylen / 8) + 2
	pk.N = bytes_to_bigint(data[2:midpoint])
	pk.E = bytes_to_int(data[midpoint:])
	return
}

func bytes_to_bigint(b []byte) (acc *big.Int) {
	acc = new(big.Int)
	acc.SetBytes(b)
	return
}

func bytes_to_int(b []byte) (i int) {
	bigint := bytes_to_bigint(b)
	i = int(bigint.Uint64())
	return
}

func rsa_encrypt(pk *rsa.PublicKey, plain []byte) (encrypted []byte) {
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pk, plain)
	if err != nil {
		fmt.Println(err)
	}
	return
}

func rsa_encrypt_pem(plain []byte) (encrypted []byte) {
	pub := pubImport("public.pem")
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pub, plain)
	if err != nil {
		fmt.Println(err)
	}
	return
}

func rsa_decrypt(encrypted []byte) (plain []byte) {
	priv := privImport("private.pem")
	label := []byte("")
	plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encrypted, label)
	if err != nil {
		fmt.Println(err)
	}
	return
}
