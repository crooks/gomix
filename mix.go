// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
	"flag"
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
	"os"
	"strings"
	"strconv"
)

const inner_header_bytes int = 328
const timestamp_intro string = "0000\x00"
const base64_line_wrap int = 40
const max_chain_length = 20

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
func generate_header(inner_bytes []byte, pubkey pubinfo) (h header) {
	/*
	Headers are not populated in the same order as they're stored in the packet.
	This is because the deskey has to be RSA encrypted early.
	*/
	h.keyid, _ = hex.DecodeString(pubkey.keyid)
	deskey := randbytes(24)
	h.enckey = rsa_encrypt(&pubkey.pk, deskey)
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
	padlen := headlen - buf.Len()
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
	padlen := inner_header_bytes - buf.Len()
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
	padlen := inner_header_bytes - buf.Len()
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
func payload_encode(plain []byte) (payload bytes.Buffer) {
	// Add 6 to text length to accommodate 4 Byte payload_length plus 1 Byte
	// each for Num Dests and Num Headers.
	payload_length := uint32(len(plain) + 2)
	lenbytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenbytes, payload_length)
	payload.Write(lenbytes)
	payload.WriteByte(0) // Number of dests
	payload.WriteByte(0) // Number of header lines
	/* According to the Mixmaster spec, the following prefix to the user-data
	should indicate an RFC2822 compliant payload.  In testing, it appears that
	Mixmaster doesn't like. */
	//payload.WriteString("##\x0D") // Mixmaster RFC2822 format indicator
	payload.Write(plain)
	payload.Write(randbytes(10240 - payload.Len()))
	return
}

// cutmarks encodes a mixmsg into a Mixmaster formatted email payload
func cutmarks(mixmsg []byte) []byte {
	buf := new(bytes.Buffer)
	buf.WriteString("::\n")
	buf.WriteString("Remailer-Type: Mixmaster 0.1\n\n")
	buf.WriteString("-----BEGIN REMAILER MESSAGE-----\n")
	buf.WriteString(strconv.Itoa(len(mixmsg)) + "\n")
	digest := md5.New()
	digest.Write(mixmsg)
	buf.WriteString(b64enc(digest.Sum(nil)) + "\n")
	buf.WriteString(b64enc(mixmsg) + "\n")
	buf.WriteString("-----END REMAILER MESSAGE-----")
	return buf.Bytes()
}

func encrypt_headers(headers, key, ivs []byte) (encrypted []byte) {
	if len(headers) % 512 != 0 {
		panic("Header is not a multiple of 512 Bytes")
	}
	if len(ivs) != 152 {
		panic("ivs should always be 19 * 8 Bytes long")
	}
	var iv []byte
	var s int // Start position in header block
	var e int // End position in header block
	header_count := len(headers) / 512
	buf := new(bytes.Buffer)
	for h := 0; h < header_count; h++ {
		iv = ivs[h * 8: (h + 1) * 8]
		s = h * 512
		e = (h + 1) * 512
		buf.Write(encrypt_des_cbc(headers[s:e], key, iv))
	}
	encrypted = buf.Bytes()
	return
}

// mixmsg encodes a plaintext message into mixmaster format.
func mixmsg(msg []byte, chainstr string) (message []byte, sendto string) {
	pubring, xref := import_pubring("pubring.mix")
	chain := chain_build(chainstr, pubring, xref)
	// Retain the address of the entry remailer, the message must be sent to it.
	sendto = chain[0]
	headers := make([]byte, 512, 10240)
	old_heads := make([]byte, 512, 9728)
	final := generate_final()
	hop := popstr(&chain)
	header := generate_header(final.bytes, pubring[hop])
	// Populate the top 512 Bytes of headers
	copy(headers[:512], header.bytes)
	// Add the clunky old Mixmaster fields to the payload and then encrypt it
	p := payload_encode(msg)
	payload := encrypt_des_cbc(p.Bytes(), final.deskey, final.iv)
	/* Final hop processing is now complete.  What follows is iterative
	intermediate hop processing. */
	for {
		// Once the chain length is zero, the message is ready for padding
		if len(chain) == 0 {
			break
		}
		/* inter only requires the previous hop address so this step is performed
		before popping the next hop from the chain. */
		inter := generate_intermediate(hop)
		hop = popstr(&chain)
		header = generate_header(inter.bytes, pubring[hop])
		/* At this point, the new header hasn't been inserted so the entire header
		chain comprises old headers that need to be encrypted with the key and ivs
		from the new header. */
		old_heads = encrypt_headers(headers, inter.deskey, inter.ivs)
		// Extend the headers slice by 512 Bytes
		headers = headers[0:len(headers) + 512]
		copy(headers[:512], header.bytes) // Write new header to first 512 Bytes
		copy(headers[512:], old_heads) // Append encrypted old headers
		payload = encrypt_des_cbc(payload, inter.deskey, inter.ivs[144:])
	}
	// Record current header length before extending and padding
	headlen_before_pad := len(headers)
	headers = headers[0:10240]
	copy(headers[headlen_before_pad:], randbytes(10240-headlen_before_pad))
	message = make([]byte, 20480)
	message = append(headers, payload...)
	return
}

func init() {
	// Remailer chain
	flag.StringVar(&flag_chain, "chain", "*,*,*", "Remailer chain")
	flag.StringVar(&flag_chain, "l", "*,*,*", "Remailer chain")
	// Recipient address
	flag.StringVar(&flag_to, "to", "", "Recipient email address")
	flag.StringVar(&flag_to, "t", "", "Recipient email address")
	// Subject header
	flag.StringVar(&flag_subject, "subject", "", "Subject header")
	flag.StringVar(&flag_subject, "s", "", "Subject header")
}

var flag_chain string
var flag_to string
var flag_subject string
var flag_args []string

func main() {
	var message []byte
	flag.Parse()
	flag_args = flag.Args()
	if len(flag_args) == 0 {
		os.Stderr.Write([]byte("No input filename provided\n"))
		os.Exit(1)
	} else if len(flag_args) == 1 {
		message = import_msg(flag_args[0])
	} else if len(flag_args) >= 2 {
		flag_to = flag_args[0]
		message = import_msg(flag_args[1])
	}
	encmsg, sendto := mixmsg(message, flag_chain)
	encmsg = cutmarks(encmsg)
	sendmail(encmsg, sendto)
	//fmt.Println(len(cutmarks(mixmsg(message, flag_chain))))
}

