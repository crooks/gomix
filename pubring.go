// vim: tabstop=2 shiftwidth=2

package main

import (
	"bufio"
	"encoding/binary"
	"crypto/rsa"
	"encoding/base64"
	"os"
	"strconv"
	"strings"
	"math/big"
)

type pubinfo struct {
	name string // Remailer Shortname
	//address is the next field in pubring but we'll use this as the key
	keyid string // 16 Byte Mixmaster KeyID
	version string // Mixmaster version
	caps string // Remailer capstring
	pk rsa.PublicKey // RSA Public Key
}

func import_pubring(filename string) (pub map[string]pubinfo,
																		  xref map[string]string) {
	var err error
	// pub = map of pubring structs
	pub = make(map[string]pubinfo)
	// xref = map of shortnames to addresses
	xref = make(map[string]string)
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	scanner := bufio.NewScanner(f)
	var elements []string
	var num_elements int
	var line string //Each line within pubring.mix
	var addy string //Remailer's address (The map key)
	var rem *pubinfo //A specific remailer's pubring struct
	var key_length int //The stated Public Key length
	var keyblock string
	var keydata []byte
	key_phase := 0
	/* Key phases are:
	0	Expecting header line
	1 Expecting Begin cutmark
	2 Expecting Keyid line
	3 Expecting key length line
	4	In keyblock
	5 Got End cutmark
	*/

	for scanner.Scan() {
		line = scanner.Text()
		switch key_phase {
		case 0:
			// Expecting key header line
			elements = strings.Split(line, " ")
			num_elements = len(elements)
			// Elements of 5 or 7 indicate a remailer header line in pubring.mix
			if (num_elements == 5 || num_elements == 7) {
				rem = new(pubinfo)
				rem.name = elements[0]
				rem.keyid = elements[2]
				rem.version = elements[3]
				rem.caps = elements[4]
				addy = elements[1]
				xref[elements[0]] = addy
				key_phase = 1
			}
		case 1:
			// Expecting Begin cutmark
			if line == "-----Begin Mix Key-----" {
				key_phase = 2
			}
		case 2:
			// Expecting Keyid line
			if line == rem.keyid {
				key_phase = 3
			} else {
				// Corrupt keyblock - header keyid doesn't match keyid in block
				key_phase = 0
				continue
			}
			key_length = 0
		case 3:
			// Expecting key length line
			key_length, err = strconv.Atoi(line)
			if err != nil {
				// The keyblock is corrupt so reset key_phase and look for another
				key_phase = 0
				continue
			}
			keyblock = ""
			key_phase = 4
		case 4:
			//In Keyblock
			if line == "-----End Mix Key-----" {
				keydata, err = base64.StdEncoding.DecodeString(keyblock)
				// encoded_keylen is the first 2 Bytes of the keyblock
				encoded_keylen := binary.LittleEndian.Uint16(keydata[0:2])
				if err != nil {
					// Invalid base64 data in keyblock
					key_phase = 0
					continue
				}
				if len(keydata) != key_length  {
					// Keyblock length doesn't match stated key length
					key_phase = 0
					continue
				}
				if int((encoded_keylen / 4) + 2) != key_length  {
					// Keyblock length differs from encoded (2 Byte) key length
					key_phase = 0
					continue
				}
				// Cut between N and E: (1024 / 8) + 2 = 130
				midpoint := (encoded_keylen / 8) + 2
				rem.pk.N = bytes_to_bigint(keydata[2:midpoint])
				rem.pk.E = bytes_to_int(keydata[midpoint:])
				pub[addy] = *rem
				key_phase = 0
			} else {
				keyblock += line
			}
		}
	}
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
