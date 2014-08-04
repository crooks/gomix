// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
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

// randint returns a cryptographically random number in range 0-max
func randint(max int) (rint int) {
	r, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		panic(err)
	}
	rint = int(r.Uint64())
	return
}

func candidates(p map[string]pubinfo, exit bool) (c []string) {
	c = make([]string, 0, len(p))
  // Create a slice of addresses (for random node selection)
  for addy := range p {
		if exit && strings.Contains(p[addy].caps, "M") {
			continue
		}
		c = append(c, addy)
	}
	return
}

// hoptest validates each chain hop and returns the hop's email address
func hoptest(chain *[]string, pub map[string]pubinfo, xref map[string]string, exit bool) (hop string) {
	hop = popstr(chain)
	addresses := candidates(pub, exit)
	var exist bool // Test for key existence
	if hop == "*" {
		// random remailer selection
		hop = addresses[randint(len(addresses) - 1)]
	} else if strings.Contains(hop, "@") {
		/* Where an ampersand exists in the hop, it's assumed to be an email
		address.  If not, it's assumed to be a shortname. */
		_, exist = pub[hop]
		if ! exist {
			panic(hop + ": Remailer address not known")
		}
	} else {
		_, exist = xref[hop]
		if ! exist {
			panic(hop + ": Remailer name not known")
		}
		// Change hop to its cross-reference by shortname
		hop = xref[hop]
	}
	fmt.Println(hop)
	return
}
