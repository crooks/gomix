// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
	"flag"
	"encoding/binary"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"bytes"
	"time"
	"hash"
	"crypto/cipher"
	"crypto/rand"
	"crypto/md5"
	"crypto/sha256"
	"crypto/hmac"
	"crypto/des"
	"crypto/aes"
	"math"
	"os"
	"strings"
	"strconv"
	"github.com/go-gcfg/gcfg"
)

const inner_header_bytes int = 328
const timestamp_intro string = "0000\x00"
const base64_line_wrap int = 40
const max_chain_length int = 20
//const max_frag_length int = 100
const max_frag_length int = 10234
const version string = "0.1b"

type Config struct {
	Files struct {
		Pubring string
		Mlist2 string
	}
  Mail struct {
		Sendmail bool
    Smtprelay string
		Smtpport int
		Envsender string
		Smtpusername string
		Smtppassword string
  }
  Stats struct {
    Minlat int
    Maxlat int
    Minrel float32
    Relfinal float32
		Numcopies int
		Distance int
  }
}

// generate_header creates the outer header.
func generate_header(inner, headers, body []byte, pubkey pubinfo, rsalen int) []byte {
	/*
	Headers are not populated in the same order as they're stored in the packet.
	This is because the deskey has to be RSA encrypted early.
	*/
	keyid, err := hex.DecodeString(pubkey.keyid)
	if err != nil {
		panic(err)
	}
	// Create 3DES key and IV
	deskey := make([]byte, 24)
	iv := make([]byte, des.BlockSize)
	copy(deskey, randbytes(24))
	copy(iv, randbytes(des.BlockSize))
	// Overwrite the plainbyte inner with its 3DES encrypted version
	copy(inner, encrypt_des_cbc(inner, deskey, iv))

	// Create the buffer that will hold the entire header
	buf := new(bytes.Buffer)
	buf.Write(keyid) // Public Keyid
	buf.WriteByte(uint8(rsalen)) // Length of RSA data
	var rsadata []byte
	if rsalen == 128 {
		rsadata = rsa_encrypt(&pubkey.pk, deskey)
	} else {
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
				AES pre-key                   [  32 bytes ]
		Initialization vector        [    8 bytes]
		Encrypted header part        [  328 bytes]
		Padding                      [    n bytes]
		-----------------------------------------
		Total                        [ 1024 bytes]
		*/
		rsa := new(bytes.Buffer)
		rsa.Write(deskey) // 3DES Key
		hmackey := randbytes(64)
		rsa.Write(hmackey) // HMAC Key
		var mac hash.Hash
		if len(headers) == 512 {
			/* This is an odd usage case. If the exit header is only 512 Bytes, the
			Anti-tag digest doesn't have sufficient material to work on.  To
			overcome that, this pads it to 1024 Bytes with random data. */
			headers = headers[0:len(headers) + 512]
			copy(headers[512:], randbytes(512))
		}

		// Do AES foo
		aes_pre_key := randbytes(32)
		aes_body_key := derive_aes_keys("body-crypt", aes_pre_key, hmackey)
		aes_inner_key := derive_aes_keys("tte-crypt", aes_pre_key, hmackey)
		aes_iv := derive_aes_keys("aes-iv", aes_pre_key, hmackey)[:16]
		// Combine encrypts in the order: inner, body, headers
		copy(body, encrypt_aes_cfb(body, aes_body_key, aes_iv))
		copy(inner, encrypt_aes_cfb(inner, aes_inner_key, aes_iv))

		if len(headers) >= 1024 {
			// Only AES encrypt existing headers if there actually are some
			aes_header_key := derive_aes_keys("header-crypt", aes_pre_key, hmackey)
			copy(headers, encrypt_aes_cfb(headers, aes_header_key, aes_iv))
			// HMAC Anti-Tag
			mac := hmac.New(sha256.New, hmackey)
			mac.Write(headers[:1024])
			rsa.Write(mac.Sum(nil)) // HMAC Anti-tag
		} else {
			// This is an Exit header so put garbage in the Anti-tag
			fmt.Println("Doing fake anti-tag on Exit")
			rsa.Write(randbytes(32)) // Fake HMAC Anti-tag
		}

		// HMAC Body
		mac = hmac.New(sha256.New, hmackey)
		mac.Write(body)
		rsa.Write(mac.Sum(nil)) // HMAC Body

		// HMAC Inner
		mac = hmac.New(sha256.New, hmackey)
		mac.Write(inner)
		rsa.Write(mac.Sum(nil)) // HMAC Inner

		rsa.Write(aes_pre_key) // AES pre-key
		if rsa.Len() != 216 {
			e := fmt.Sprintf("Expected 216 Bytes of RSA data.  Got %d Bytes", rsa.Len())
			panic(e)
		}

		// Encrypt the RSA data
		rsadata = rsa_encrypt(&pubkey.pk, rsa.Bytes())
	}
	buf.Write(rsadata)
	buf.Write(iv) // 3DES IV
	buf.Write(inner) // Inner header
	// Pad the header to its defined length of 512 or 1024 Bytes
	rsadatalen := len(rsadata)
	if rsalen == 128 {
		if rsadatalen != 128 {
			e := fmt.Sprintf("Expected 128 Bytes of RSA data.  Got %d Bytes", rsadatalen)
			panic(e)
		}
		if buf.Len() != 481 {
			e := fmt.Sprintf("Expected 481 Bytes of header data.  Got %d Bytes", buf.Len())
			panic(e)
		}
		buf.Write(randbytes(512 - buf.Len()))
	} else {
		switch rsalen {
		case 2:
			if rsadatalen != 256 {
				e := fmt.Sprintf("Expected 256 Bytes of RSA data.  Got %d Bytes", rsadatalen)
				panic(e)
			}
			if buf.Len() != 609 {
				e := fmt.Sprintf("Expected 609 Bytes of header data.  Got %d Bytes", buf.Len())
				panic(e)
			}
		case 3:
			if rsadatalen != 384 {
				e := fmt.Sprintf("Expected 384 Bytes of RSA data.  Got %d Bytes", rsadatalen)
				panic(e)
			}
			if buf.Len() != 737 {
				e := fmt.Sprintf("Expected 737 Bytes of header data.  Got %d Bytes", buf.Len())
				panic(e)
			}
		case 4:
			if rsadatalen != 512 {
				e := fmt.Sprintf("Expected 512 Bytes of RSA data.  Got %d Bytes", rsadatalen)
				panic(e)
			}
			if buf.Len() != 865 {
				e := fmt.Sprintf("Expected 865 Bytes of header data.  Got %d Bytes", buf.Len())
				panic(e)
			}
		default:
			e:= fmt.Sprintf("RSA data of %d Bytes does not conform to specification", rsadatalen)
			panic(e)
		}
		buf.Write(randbytes(1024 - buf.Len()))
	}
	if buf.Len() != 512 && buf.Len() != 1024 {
		panic("Invalid header size")
	}
	return buf.Bytes()
}

// derive_aes_keys constructs an AES key using the hmac of a static string
// combined with a pre-key.
func derive_aes_keys(plain string, pre_key, hmackey []byte) []byte {
	buf := new(bytes.Buffer)
	buf.WriteString(plain)
	buf.Write(pre_key)
	mac := hmac.New(sha256.New, hmackey)
	mac.Write(buf.Bytes())
	return mac.Sum(nil)
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

// generate_final creates a final-hop inner header.
func generate_final(msgid, packetid, body []byte) []byte {
	buf := new(bytes.Buffer)
	buf.Write(packetid) // Packet ID
	deskey := randbytes(24)
	buf.Write(deskey) // 3DES Key
	buf.WriteByte(uint8(1)) // Packet Type 1
	buf.Write(msgid) // Message ID
	iv := randbytes(des.BlockSize)
	// Encrypt the body
	fmt.Println("Pre DES in gen final:", hex.EncodeToString(body[:30]))
	copy(body, encrypt_des_cbc(body, deskey, iv))
	buf.Write(iv) // IV
	buf.Write(timestamp()) // Timestamp
	digest := md5.New()
	digest.Write(buf.Bytes())
	buf.Write(digest.Sum(nil)) // Inner Digest
	padlen := inner_header_bytes - buf.Len()
	buf.Write(randbytes(padlen))
	return buf.Bytes()
}

// generate_partial creates a final-hop partial (type 2) inner header.
func generate_partial(msgid, packetid, body []byte, cnum, numc int) []byte {
	buf := new(bytes.Buffer)
	buf.Write(packetid) // Packet ID
	deskey := randbytes(24)
	buf.Write(deskey) // 3DES Key
	buf.WriteByte(uint8(2)) // Packet Type 2
	buf.WriteByte(uint8(cnum)) // Chunk Number
	buf.WriteByte(uint8(numc)) // Number of chunks
	buf.Write(msgid) // Message ID
	iv := randbytes(des.BlockSize)
	// Encrypt the body
	copy(body, encrypt_des_cbc(body, deskey, iv))
	buf.Write(iv) // IV
	buf.Write(timestamp()) // Timestamp
	digest := md5.New()
	digest.Write(buf.Bytes())
	buf.Write(digest.Sum(nil)) // Inner Digest
	padlen := inner_header_bytes - buf.Len()
	buf.Write(randbytes(padlen))
	return buf.Bytes()
}

// generate_intermediate creates an intermediate-hop inner header.  The only
// input variable is a string containing the email address of the next hop.
func generate_intermediate(nexthop string, headers, body []byte) []byte {
	buf := new(bytes.Buffer)
	buf.Write(randbytes(16)) // Packet ID
	deskey := randbytes(24)
	buf.Write(deskey) // 3DES Key
	buf.WriteByte(uint8(0)) // Packet Type 0
	ivs := randbytes(des.BlockSize * 19)
	/* At this point, the new header hasn't been inserted so the entire header
	chain comprises old headers that need to be encrypted with the key and ivs
	from the new header. */
	encrypt_headers(headers, deskey, ivs)
	// The body is encrypted with the last of the 19 IVs
	copy(body, encrypt_des_cbc(body, deskey, ivs[144:]))
	buf.Write(ivs) // IV
	nhpad := 80 - len(nexthop)
	nh := nexthop + strings.Repeat("\x00", nhpad)
	buf.WriteString(nh) // Next Hop
	buf.Write(timestamp()) // Timestamp
	digest := md5.New()
	digest.Write(buf.Bytes())
	buf.Write(digest.Sum(nil)) // Digest
	padlen := inner_header_bytes - buf.Len()
	buf.Write(randbytes(padlen))
	return buf.Bytes()
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

func decrypt_aes_cfb(encrypted, key, iv []byte) (plain []byte) {
	block, err := aes.NewCipher(key)
  if err != nil {
		panic(err)
	}
	plain = make([]byte, len(encrypted))
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(plain, encrypted)
	return
}


// body_encode converts a plaintext message to Mixmaster's payload format
func body_encode(plain []byte, cnum int) []byte {
	/* Chunk number is used to determine that length needs to be +2 on the
	first chunk to accommodate the dests and headers.*/
	body := new(bytes.Buffer)
	body_length := len(plain)
	if cnum == 1 {
		body_length += 2
	}
	lenbytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenbytes, uint32(body_length))
	body.Write(lenbytes)
	if cnum == 1 {
		body.WriteByte(0) // Number of dests
		body.WriteByte(0) // Number of header lines
	}
	/* According to the Mixmaster spec, the following prefix to the user-data
	should indicate an RFC2822 compliant payload.  In testing, it appears that
	Mixmaster doesn't like it. */
	//payload.WriteString("##\x0D") // Mixmaster RFC2822 format indicator
	body.Write(plain)
	if body.Len() < 10240 {
		// Pad payload with random bytes
		body.Write(randbytes(10240 - body.Len()))
	} else if body.Len() > 10240 {
		// Assertion check
		panic("Message body exceeds 10240 byte limit")
	}
	return body.Bytes()
}

// cutmarks encodes a mixmsg into a Mixmaster formatted email payload
func cutmarks(mixmsg []byte) []byte {
	buf := new(bytes.Buffer)
	buf.WriteString("::\n")
	header := fmt.Sprintf("Remailer-Type: Mixmaster Go %s\n\n", version)
	buf.WriteString(header)
	buf.WriteString("-----BEGIN REMAILER MESSAGE-----\n")
	buf.WriteString(strconv.Itoa(len(mixmsg)) + "\n")
	digest := md5.New()
	digest.Write(mixmsg)
	buf.WriteString(b64enc(digest.Sum(nil)) + "\n")
	buf.WriteString(b64enc(mixmsg) + "\n")
	buf.WriteString("-----END REMAILER MESSAGE-----")
	return buf.Bytes()
}

func encrypt_headers(headers, deskey, ivs []byte) {
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
	for h := 0; h < header_count; h++ {
		iv = ivs[h * 8: (h + 1) * 8]
		s = h * 512
		e = (h + 1) * 512
		copy(headers[s:e], encrypt_des_cbc(headers[s:e], deskey, iv))
	}
}

// mixprep fetches the plaintext and prepares it for mix encoding
func mixprep() {
	var err error
	var message []byte
	var cnum int // Chunk number
	var numc int // Number of chunks
	if len(flag_args) == 0 && ! flag_stdin {
		os.Stderr.Write([]byte("No input filename provided\n"))
		os.Exit(1)
	} else if flag_stdin {
		// Flag instructs message should be read from stdin
		message, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if len(flag_args) == 1 {
			// A single arg on an stdin msg implies a recipient address
			flag_to = flag_args[0]
		}
	} else if len(flag_args) == 1 {
		// A single arg should be the filename
		message = import_msg(flag_args[0])
	} else if len(flag_args) >= 2 {
		// Two args should be recipient and filename
		flag_to = flag_args[0]
		message = import_msg(flag_args[1])
	}
	msglen := len(message)
	if msglen == 0 {
		fmt.Fprintln(os.Stderr, "No bytes in message")
		os.Exit(1)
	}
	// Create the Public Keyring
	pubring, xref := import_pubring(cfg.Files.Pubring)
	// Populate keyring's uptime and latency fields
	_ = import_mlist2(cfg.Files.Mlist2, pubring, xref)
	in_chain := strings.Split(flag_chain, ",")
	msgid := randbytes(16)
	numc = int(math.Ceil(float64(msglen) / float64(max_frag_length)))
	cnum = 1
	var exitnode string // Address of exit node (for multiple copy chains)
	var got_exit bool // Flag to indicate an exit node has been selected
	var packetid []byte // Final hop Packet ID
	var first_byte int // First byte of message slice
	var last_byte int // Last byte of message slice
	for cnum = 1; cnum <= numc; cnum++ {
		// First byte of message fragment
		first_byte = (cnum - 1) * max_frag_length
		last_byte = first_byte + max_frag_length
		// Don't slice beyond the end of the message
		if last_byte > msglen {
			last_byte = msglen
		}
		got_exit = false
		packetid = randbytes(16)
		// If no copies flag is specified, use the config file NUMCOPIES
		if flag_copies == 0 {
			flag_copies = cfg.Stats.Numcopies
		}
		if flag_copies > 10 {
			// Limit copies to a maximum of 10
			flag_copies = 10
		}
		for n := 0; n < flag_copies; n++ {
			if got_exit {
				// Set the last node in the chain to the previously select exitnode
				in_chain[len(in_chain) - 1] = exitnode
			}
			chain := chain_build(in_chain, pubring, xref)
			fmt.Println(chain)
			if ! got_exit {
				exitnode = chain[len(chain) - 1]
				got_exit = true
			}
			encmsg, sendto := mixmsg(message[first_byte:last_byte], msgid, packetid, chain, cnum, numc, pubring, xref)
			fmt.Println("Post AES in mixprep:", hex.EncodeToString(encmsg[10240:10270]))
			encmsg = cutmarks(encmsg)
			if cfg.Mail.Sendmail {
				sendmail(encmsg, sendto)
			} else {
				smtprelay(encmsg, sendto)
			}
			//fmt.Println(len(encmsg), sendto)
		} // End of copies loop
	} // End of fragments loop
}

// keylen uses the encoded pubkey length to determine the header size and rsalen
func keylen(l uint16) (headlen, rsalen int) {
	switch l {
	case 1024:
		headlen = 512
		rsalen = 128
	case 2048:
		headlen = 1024
		rsalen = 2
	case 3072:
		headlen = 1024
		rsalen = 3
	case 4096:
		headlen = 1024
		rsalen = 4
	default:
		panic("Unexpected Public Key length")
	}
	return
}

// mixmsg encodes a plaintext fragment into mixmaster format.
func mixmsg(msg, msgid, packetid []byte, chain []string, cnum, numc int,
						pubring map[string]pubinfo, xref map[string]string) (payload []byte, sendto string) {
	inner := make([]byte, 328) // Bytes of inner header (inter, final or partial types)
	// Retain the address of the entry remailer, the message must be sent to it.
	sendto = chain[0]
	body := make([]byte, 10240)
	// Convert the plaintext to mixmaster body format
	copy(body, body_encode(msg, cnum))
	if numc == 1 {
		// Single fragment message so use a type 1 final header
		copy(inner, generate_final(msgid, packetid, body))
	} else {
		copy(inner, generate_partial(msgid, packetid, body, cnum, numc))
	}
	hop := popstr(&chain)
	var headlen int // Length of header required to accomodate this key
	var rsalen int // RSA data length to write into header (128, 2, 3 or 4)
	headlen, rsalen = keylen(pubring[hop].keylen)
	// Initially create headers with sufficient length for the exit header
	headers := make([]byte, headlen, 10240)
	// Populate the top headlen Bytes of headers
	copy(headers[:headlen], generate_header(inner, headers, body, pubring[hop], rsalen))
	/* Final hop processing is now complete.  What follows is iterative
	intermediate hop processing. */
	for {
		// Once the chain length is zero, the message is ready for padding
		if len(chain) == 0 {
			break
		}
		/* intermediate headers include the previous hop address so this step is performed
		before popping the next hop from the chain. */
		copy(inner, generate_intermediate(hop, headers, body))
		hop = popstr(&chain)
		// Establish how big a header will be for this specific hop
		headlen, rsalen = keylen(pubring[hop].keylen)
		// Extend the headers slice by headlen Bytes
		headers = headers[0:len(headers) + headlen]
		copy(headers[headlen:], headers) // Move all the headers down by 512 bytes
		// Write new header to first 512 Bytes
		copy(headers[:headlen], generate_header(inner, headers, body, pubring[hop], rsalen))
	}
	// Record current header length before extending and padding
	headlen_before_pad := len(headers)
	headers = headers[0:10240]
	copy(headers[headlen_before_pad:], randbytes(10240-headlen_before_pad))
	payload = make([]byte, 20480)
	fmt.Println("Post AES in mixmsg:", hex.EncodeToString(body[:30]))
	copy(payload[:10240], headers)
	copy(payload[10240:], body)
	return
}

func meminfo() {
	procdev := fmt.Sprintf("/proc/%d/status", os.Getpid())
	fd, _ := os.Open(procdev)
	defer fd.Close()
	b := make([]byte, 4096)
	fd.Read(b)
	for _, lin := range strings.Split(string(b), "\n") {
	  if "Vm" == lin[:2] {
		  fmt.Printf("%s\n", lin)
		}
	}
}

func init() {
	var err error
	// Remailer chain
	flag.StringVar(&flag_chain, "chain", "*,*,*", "Remailer chain")
	flag.StringVar(&flag_chain, "l", "*,*,*", "Remailer chain")
	// Recipient address
	flag.StringVar(&flag_to, "to", "", "Recipient email address")
	flag.StringVar(&flag_to, "t", "", "Recipient email address")
	// Subject header
	flag.StringVar(&flag_subject, "subject", "", "Subject header")
	flag.StringVar(&flag_subject, "s", "", "Subject header")
	// Number of copies
	flag.IntVar(&flag_copies, "copies", 0, "Number of copies")
	flag.IntVar(&flag_copies, "c", 0, "Number of copies")
	// Config file
	flag.StringVar(&flag_config, "config", "mix.cfg", "Config file")
	// Read STDIN
	flag.BoolVar(&flag_stdin, "read-mail", false, "Read a message from stdin")
	flag.BoolVar(&flag_stdin, "R", false, "Read a message from stdin")
	// Print Version
	flag.BoolVar(&flag_version, "version", false, "Print version string")
	flag.BoolVar(&flag_version, "V", false, "Print version string")
	// Memory usage
	flag.BoolVar(&flag_meminfo, "meminfo", false, "Print memory info")

	// Set defaults and read config file
	cfg.Files.Pubring = "pubring.mix"
	cfg.Files.Mlist2 = "mlist2.txt"
	cfg.Mail.Smtprelay = "127.0.0.1"
	cfg.Mail.Smtpport = 25
	cfg.Mail.Envsender = "nobody@nowhere.invalid"
	cfg.Mail.Sendmail = true
	cfg.Mail.Smtpusername = ""
	cfg.Mail.Smtppassword = ""
	cfg.Stats.Minrel = 98.0
	cfg.Stats.Relfinal = 99.0
	cfg.Stats.Minlat = 2
	cfg.Stats.Maxlat = 60
	cfg.Stats.Numcopies = 1
	cfg.Stats.Distance = 2

	err = gcfg.ReadFileInto(&cfg, flag_config)
  if err != nil {
    fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
  }
}

var flag_chain string
var flag_to string
var flag_subject string
var flag_args []string
var flag_config string
var flag_copies int
var flag_stdin bool
var flag_version bool
var flag_meminfo bool
var cfg Config

func main() {
	flag.Parse()
	flag_args = flag.Args()
	if flag_version {
		fmt.Println(version)
	} else {
		mixprep()
	}
	if flag_meminfo {
		meminfo()
	}
}

