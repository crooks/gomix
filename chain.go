// vim: tabstop=2 shiftwidth=2

package main

import (
	"crypto/rand"
	"math/big"
	"strings"
)

// popstr takes a pointer to a string slice and pops the last element
func popstr(s *[]string) (element string) {
	slice := *s
	element, slice = slice[len(slice) - 1], slice[:len(slice) - 1]
	*s = slice
	return
}

// insstr inserts a string (text) into a slice at position pos
func insstr(s *[]string, text string, pos int) (length int) {
	slice := *s
	slice = append(slice, "foo")
	copy(slice[pos + 1:], slice[pos:])
	slice[pos] = text
	*s = slice
	length = len(slice)
	return
}

// randint returns a cryptographically random number in range 0-max
func randint(max int) (rint int) {
	r, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		panic(err)
	}
	rint = int(r.Uint64())
	return
}

// candidates returns a slice of remailer addresses suitable for a given hop
func candidates(p map[string]pubinfo, exit bool) (c []string) {
	c = make([]string, 0, len(p))
  // Create a slice of addresses (for random node selection)
  for addy := range p {
		if exit && strings.Contains(p[addy].caps, "M") {
			// Exits are required and this is a Middle
			continue
		}
		c = append(c, addy)
	}
	return
}

// chain_build takes a chain string and constructs a valid remailer chain
func chain_build(chainstr string, pub map[string]pubinfo, xref map[string]string) (out_chain []string) {
	var exist bool // Test for key existence
	var addresses []string // Candidate remailers for each hop
	in_chain := strings.Split(chainstr, ",")
	out_chain = make([]string, 0, len(in_chain))
	for {
		hop := popstr(&in_chain)
		if hop == "*" {
			// Random remailer selection
			if len(out_chain) == 0 {
				addresses = candidates(pub, true)
			} else {
				addresses = candidates(pub, false)
			}
			hop = addresses[randint(len(addresses) - 1)]
		} else if strings.Contains(hop, "@") {
			// Selection via remailer email address
			/* Where an ampersand exists in the hop, it's assumed to be an email
			address.  If not, it's assumed to be a shortname. */
			_, exist = pub[hop]
			if ! exist {
				panic(hop + ": Remailer address not known")
			}
		} else {
			// Selection via remailer shortname
			_, exist = xref[hop]
			if ! exist {
				panic(hop + ": Remailer name not known")
			}
			// Change hop to its cross-reference by shortname
			hop = xref[hop]
		}
		// Insert new hop at the start of the output chain
		_ = insstr(&out_chain, hop, 0)
		if len(in_chain) == 0 {
			break
		}
	}
	return
}
