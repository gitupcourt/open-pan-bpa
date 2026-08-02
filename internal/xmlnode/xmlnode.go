// Package xmlnode provides a small generic XML tree for navigating PAN-OS
// configuration documents. It exists so the parser can walk arbitrary config
// structure without maintaining struct definitions for every PAN-OS schema
// element, and without external XPath dependencies.
package xmlnode

import (
	"encoding/xml"
	"io"
	"strings"
)

// Node is one XML element: name, attributes, text, children.
type Node struct {
	Name     string
	Attrs    map[string]string
	Text     string
	Children []*Node
}

// Parse builds a Node tree from r. The reader should already be size-capped
// by the caller (see ingest) — Parse itself imposes no limits.
func Parse(r io.Reader) (*Node, error) {
	dec := xml.NewDecoder(r)
	var root *Node
	var stack []*Node
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := &Node{Name: t.Name.Local}
			if len(t.Attr) > 0 {
				n.Attrs = make(map[string]string, len(t.Attr))
				for _, a := range t.Attr {
					n.Attrs[a.Name.Local] = a.Value
				}
			}
			if len(stack) == 0 {
				root = n
			} else {
				p := stack[len(stack)-1]
				p.Children = append(p.Children, n)
			}
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].Text += string(t)
			}
		}
	}
	if root == nil {
		return nil, io.ErrUnexpectedEOF
	}
	return root, nil
}

// Attr returns the named attribute or "".
func (n *Node) Attr(name string) string {
	if n == nil || n.Attrs == nil {
		return ""
	}
	return n.Attrs[name]
}

// First walks the path of child element names and returns the first match at
// each step, or nil if any step is missing.
func (n *Node) First(path ...string) *Node {
	cur := n
	for _, name := range path {
		if cur == nil {
			return nil
		}
		var next *Node
		for _, c := range cur.Children {
			if c.Name == name {
				next = c
				break
			}
		}
		cur = next
	}
	return cur
}

// All returns every child of the node reached by path[:-1] whose name matches
// the final path element. All() with no path returns n's children.
func (n *Node) All(path ...string) []*Node {
	if n == nil {
		return nil
	}
	if len(path) == 0 {
		return n.Children
	}
	parent := n
	if len(path) > 1 {
		parent = n.First(path[:len(path)-1]...)
	}
	if parent == nil {
		return nil
	}
	var out []*Node
	for _, c := range parent.Children {
		if c.Name == path[len(path)-1] {
			out = append(out, c)
		}
	}
	return out
}

// TrimText returns the node's text content with surrounding whitespace removed.
func (n *Node) TrimText() string {
	if n == nil {
		return ""
	}
	return strings.TrimSpace(n.Text)
}

// ChildText is First(path...).TrimText().
func (n *Node) ChildText(path ...string) string {
	return n.First(path...).TrimText()
}

// Members returns the text of each <member> child under path — the standard
// PAN-OS list encoding.
func (n *Node) Members(path ...string) []string {
	target := n
	if len(path) > 0 {
		target = n.First(path...)
	}
	if target == nil {
		return nil
	}
	var out []string
	for _, c := range target.Children {
		if c.Name == "member" {
			out = append(out, c.TrimText())
		}
	}
	return out
}

// Entries returns the <entry> children under path (PAN-OS keyed collections).
func (n *Node) Entries(path ...string) []*Node {
	p := append(append([]string{}, path...), "entry")
	return n.All(p...)
}
