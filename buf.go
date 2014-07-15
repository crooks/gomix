// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
	"encoding/binary"
	"encoding/base64"
	"encoding/hex"
	"bytes"
	"time"
	"crypto/cipher"
	"crypto/rand"
	"crypto/md5"
	"crypto/des"
	"crypto/aes"
	"strings"
	"strconv"
)

const inner_header_bytes int = 328
const timestamp_intro string = "0000\x00"
const base64_line_wrap int = 40

type final_hop struct {
	packetid []byte // 16 Byte Packet-ID
	deskey []byte // 24 Byte DES key
	pkttype uint8 // Packet Type (Intermediate(0) or Final(1)
  msgid []byte // 16 Byte Message-ID
	iv []byte // 8 Byte IV
  timestamp []byte // 7 Bytes (Intro = 48,48,48,48,0)
	digest []byte // 16 Byte MD5 digest
	bytes []byte // All the final_hop headers, in a 328 Byte array
}

type intermediate_hop struct {
	packetid []byte // 16 Byte Packet-ID
	deskey []byte // 24 Byte DES key
	pkttype uint8 // Packet Type (Intermediate(0) or Final(1)
  ivs []byte // 152 Byte IVs (19 * 8)
	nexthop []byte // 80 Byte next hop address
  timestamp []byte // 7 Bytes (Intro = 48,48,48,48,0)
	digest []byte // 16 Byte MD5 digest
	bytes []byte  // All the intermediate_hop headers in a 328 Byte array
}

type header struct {
	keyid []byte // 16 Byte Public KeyID
	rsalen uint8 // 1 Byte RSA Data Length
	/*
	To maintain compatibility with older Mixmaster versions, the rsalen is
	interpreted in the following manner:-
	128 = 128 Bytes RSA (1024 bit encryption)
	  2 = 256 Bytes RSA (2048 bit encryption)
		3 = 384 Bytes RSA (3072 bit encryption)
		4 = 512 Bytes RSA (4096 bit encryption)
	*/
	enckey []byte // RSA encoded session key (for inner header)
	iv []byte // 8 Byte 3DES IV (for inner header)
	encinner []byte // 328 Byte encrypted inner header
	bytes []byte // The entire header in a Byte array
}

// generate_header creates the outer header.
func generate_header(inner_bytes []byte) (h header) {
	/*
	Headers are not populated in the same order as they're stored in the packet.
	This is because the deskey has to be RSA encrypted early.
	*/
	keyid := "fafca5bea2ba5417298755e5d1287756"
	h.keyid, _ = hex.DecodeString(keyid)
	deskey := randbytes(24)
	pk := mix_import_pk("pubring.mix", keyid)
	h.enckey = rsa_encrypt(&pk, deskey)
	// The outer header is padded to 512 Bytes for 1024 bit keys and to
	// 1024 Bytes for all other key sizes.
	headlen := 1024
	switch len(h.enckey) {
		case 128:
			h.rsalen = 128
			headlen = 512  // All other cases use 1024 Byte headers
		case 256:
			h.rsalen = 2
		case 384:
			h.rsalen = 3
		case 512:
			h.rsalen = 4
	}
	h.iv = randbytes(des.BlockSize)

	//fmt.Printf("keyid=%d, key=%d, inner=%d\n", len(h.keyid), len(h.enckey), len(inner_bytes))
	h.encinner = encrypt_des_cbc(inner_bytes, deskey, h.iv)

	buf := new(bytes.Buffer)
	buf.Write(h.keyid)
	buf.WriteByte(h.rsalen)
	buf.Write(h.enckey)
	buf.Write(h.iv)
	buf.Write(h.encinner)
	if headlen >= 1024 {
		// This is an extended header and needs further work
		/* Here follows the specification as I interpret it:-
		Public key ID                [   16 bytes]
		Length of RSA-encrypted data [    1 byte ]
		RSA-encrypted data           [  512 bytes]
		3DES Session Key              [  24 bytes ]
				Random HMAC Key               [  64 bytes ]
				HMAC hash (Anti-tag)          [  32 bytes ]
				HMAC hash (Body)              [  32 bytes ]
				HMAC hash (328 Byte Enc Head) [  32 bytes ]
				AES Key                       [  32 bytes ]
		Initialization vector        [    8 bytes]
		Encrypted header part        [  328 bytes]
		Padding                      [    n bytes]
		-----------------------------------------
		Total                        [ 1024 bytes]
		*/
	}
	// Pad the header to its defined length of 512 or 1024 Bytes
	padlen := headlen - len(buf.Bytes())
	buf.Write(randbytes(padlen))
	h.bytes = buf.Bytes()
	return
}

// randbytes returns n Bytes of random data
func randbytes(n int) []byte {
  b := make([]byte, n)
  _, err := rand.Read(b)
  if err != nil {
    fmt.Println("Error:", err)
  }
  return b
}

// timestamp creates a Mixmaster formatted timestamp, consisting of an intro
// string concatented to the number of days since Epoch (little Endian).
func timestamp() []byte {
	d := uint16(time.Now().UTC().Unix() / 86400)
	days := make([]byte, 2)
	binary.LittleEndian.PutUint16(days, d)
	stamp := append([]byte(timestamp_intro), days...)
	return stamp
}

// b64enc takes a byte array as input and returns it as a base64 encoded
// string.  The output string is wrapped to a predefined line length.
func b64enc(data []byte) string {
	return wrap(base64.StdEncoding.EncodeToString(data))
}

// wrap takes a long string and wraps it to lines of a predefined length.
// The intention is to feed it a base64 encoded string.
func wrap(str string) (newstr string) {
	var substr string
	var end int
	strlen := len(str)
	for i := 0; i <= strlen; i += base64_line_wrap {
		end = i + base64_line_wrap
		if end > strlen {
			end = strlen
		}
		substr = str[i:end] + "\n"
		newstr += substr
	}
	// Strip the inevitable trailing LF
	newstr = strings.TrimRight(newstr, "\n")
	return
}

// generate_final creates a final-hop inner header.  No input variables are
// required as all components of the header are generated internally.
func generate_final() (h final_hop) {
	h.packetid = randbytes(16)
	h.deskey = randbytes(24)
	h.pkttype = uint8(1)
	h.msgid = randbytes(16)
	h.iv = randbytes(des.BlockSize)
	h.timestamp = timestamp()

	buf := new(bytes.Buffer)
	buf.Write(h.packetid)
	buf.Write(h.deskey)
	buf.WriteByte(h.pkttype)
	buf.Write(h.msgid)
	buf.Write(h.iv)
	buf.Write(h.timestamp)
	digest := md5.New()
	digest.Write(buf.Bytes())
	h.digest = digest.Sum(nil)
	buf.Write(h.digest)
	padlen := inner_header_bytes - len(buf.Bytes())
	buf.Write(randbytes(padlen))
	h.bytes = buf.Bytes()
	return
}

// generate_intermediate creates an intermediate-hop inner header.  The only
// input variable is a string containing the email address of the next hop.
func generate_intermediate(nexthop string) (h intermediate_hop) {
	h.packetid = randbytes(16)
	h.deskey = randbytes(24)
	h.pkttype = 0
	h.ivs = randbytes(152)
	nexthoppad := 80 - len(nexthop)
	h.nexthop = []byte(nexthop + strings.Repeat("\x00", nexthoppad))
	h.timestamp = timestamp()

	buf := new(bytes.Buffer)
	buf.Write(h.packetid)
	buf.Write(h.deskey)
	buf.WriteByte(h.pkttype)
	buf.Write(h.ivs)
	buf.Write(h.nexthop)
	buf.Write(h.timestamp)
	digest := md5.New()
	digest.Write(buf.Bytes())
	h.digest = digest.Sum(nil)
	buf.Write(h.digest)
	padlen := inner_header_bytes - len(buf.Bytes())
	buf.Write([]byte(strings.Repeat("\x00", padlen)))
	h.bytes = buf.Bytes()
	return
}

// encrypt_des_cfb performs Triple DES CFB encryption on a byte slice.  For
// input, it expects to receive a reference to a prefedined slice (enc), a
// slice to be encrypted (plain), a 3DES key of size 24 and an initialization
// vector (iv).
func encrypt_des_cfb(plain, key, iv []byte) (encrypted []byte) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		panic(err)
	}
	encrypted = make([]byte, len(plain))
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(encrypted, plain)
	return
}

// encrypt_des_cbc performs Triple DES CBC encryption on a byte slice.  For
// input, it expects to receive a reference to a prefedined slice (enc), a
// slice to be encrypted (plain), a 3DES key of size 24 and an initialization
// vector (iv).
func encrypt_des_cbc(plain, key, iv []byte) (encrypted []byte) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		panic(err)
	}
	encrypted = make([]byte, len(plain))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encrypted, plain)
	return
}

// encrypt_aes_cfb performs AES CFB encryption on a byte slice.  For input, it
// expects to receive a reference to a prefedined slice (enc), a slice
// to be encrypted (plain), an AES key of size 16, 24 or 32 and an
// initialization vector (iv).
func encrypt_aes_cfb(plain, key, iv []byte) (encrypted []byte) {
  block, err := aes.NewCipher(key)
  if err != nil {
    panic(err)
  }
	encrypted = make([]byte, len(plain))
  stream := cipher.NewCFBEncrypter(block, iv)
  stream.XORKeyStream(encrypted, plain)
  return
}

// payload_encode converts a plaintext message to Mixmaster's payload format
func payload_encode(text string) (payload bytes.Buffer) {
	// Add 6 to text length to accommodate 4 Byte payload_length plus 1 Byte
	// each for Num Dests and Num Headers.
	payload_length := uint32(len(text) + 6)
	lenbytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenbytes, payload_length)
	payload.Write(lenbytes)
	payload.WriteByte(0) // Number of dests
	payload.WriteByte(0) // Nymber of header lines
	payload.Write([]byte(text))
	payload.Write(randbytes(10240 - len(payload.Bytes())))
	return
}

// cutmarks encodes a mixmsg into a Mixmaster formatted email payload
func cutmarks(mixmsg *bytes.Buffer) (mixtext string) {
	mixtext += "::\n"
	mixtext += "Remailer-Type: GoMix 0.1\n\n"
	mixtext += "-----BEGIN REMAILER MESSAGE-----\n"
	mixtext += strconv.Itoa(len(mixmsg.Bytes())) + "\n"
	digest := md5.New()
	digest.Write(mixmsg.Bytes())
	mixtext += b64enc(digest.Sum(nil)) + "\n"
	mixtext += b64enc(mixmsg.Bytes()) + "\n"
	mixtext +="-----END REMAILER MESSAGE-----"
	return
}

func main() {
	message := new(bytes.Buffer)
	final := generate_final()
	header := generate_header(final.bytes)
	message.Write(header.bytes)
	message.Write(randbytes(19 * 512))
	text := "##\n"
	text += "From: nobody@testing.invalid\n"
	text += "To: steve@mixmin.net\n"
	text += "Subject: Testing Gomix\n\n"
	text += "This is a gomix test payload."
	payload := payload_encode(text)
	message.Write(encrypt_des_cbc(payload.Bytes(), final.deskey, final.iv))

	fmt.Println(cutmarks(message))
}