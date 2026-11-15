package engine

// automaton is an Aho-Corasick automaton that finds which keywords occur in
// a text. It ignores ASCII case. It is a full DFA: each byte costs one table
// lookup.
type automaton struct {
	// class maps a byte to its column in delta. Bytes that do not occur in
	// any keyword share the column 0.
	class  [256]uint8
	nclass int
	delta  []int32
	// out lists, for each state, the keywords that end at the state. The
	// list includes the keywords of the suffix states.
	out [][]int32
}

func lowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 'a' - 'A'
	}
	return b
}

func newAutomaton(keywords []string) *automaton {
	a := &automaton{}
	// Assign a column to each lowercase byte that occurs in a keyword.
	next := 1
	for _, k := range keywords {
		for i := 0; i < len(k); i++ {
			c := lowerASCII(k[i])
			if a.class[c] == 0 {
				if next > 255 {
					// More than 255 distinct bytes cannot occur in practice.
					panic("engine: too many distinct keyword bytes")
				}
				a.class[c] = uint8(next)
				next++
			}
		}
	}
	for b := 'A'; b <= 'Z'; b++ {
		a.class[b] = a.class[b+'a'-'A']
	}
	a.nclass = next

	// Build the trie. A goto value of -1 means "no edge".
	type node struct {
		next []int32
		out  []int32
	}
	newNode := func() node {
		n := node{next: make([]int32, a.nclass)}
		for i := range n.next {
			n.next[i] = -1
		}
		return n
	}
	nodes := []node{newNode()}
	for ki, k := range keywords {
		s := int32(0)
		for i := 0; i < len(k); i++ {
			c := a.class[lowerASCII(k[i])]
			if nodes[s].next[c] < 0 {
				nodes = append(nodes, newNode())
				nodes[s].next[c] = int32(len(nodes) - 1)
			}
			s = nodes[s].next[c]
		}
		nodes[s].out = append(nodes[s].out, int32(ki))
	}

	// Compute failure links in breadth-first order and resolve every
	// missing edge to a full DFA transition.
	fail := make([]int32, len(nodes))
	a.delta = make([]int32, len(nodes)*a.nclass)
	a.out = make([][]int32, len(nodes))
	queue := make([]int32, 0, len(nodes))
	for c := 0; c < a.nclass; c++ {
		t := nodes[0].next[c]
		if t < 0 {
			a.delta[c] = 0
			continue
		}
		a.delta[c] = t
		fail[t] = 0
		queue = append(queue, t)
	}
	a.out[0] = nodes[0].out
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		a.out[s] = append(append([]int32(nil), nodes[s].out...), a.out[fail[s]]...)
		for c := 0; c < a.nclass; c++ {
			t := nodes[s].next[c]
			if t < 0 {
				a.delta[int(s)*a.nclass+c] = a.delta[int(fail[s])*a.nclass+c]
				continue
			}
			a.delta[int(s)*a.nclass+c] = t
			fail[t] = a.delta[int(fail[s])*a.nclass+c]
			queue = append(queue, t)
		}
	}
	return a
}

// scan calls hit for each keyword occurrence in data, with the offset
// after the last byte of the occurrence. The offsets do not decrease.
func (a *automaton) scan(data []byte, hit func(keyword int32, end int)) {
	s := int32(0)
	n := a.nclass
	for i, b := range data {
		s = a.delta[int(s)*n+int(a.class[b])]
		if out := a.out[s]; len(out) > 0 {
			for _, k := range out {
				hit(k, i+1)
			}
		}
	}
}
