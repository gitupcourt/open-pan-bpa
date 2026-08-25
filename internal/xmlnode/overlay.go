package xmlnode

// Overlay merges add's subtree into base, with base taking priority — the
// PAN-OS template-stack composition rule: the higher-priority (earlier)
// template's value wins per element path, and content the base doesn't
// define is inherited from lower-priority templates.
//
// Matching rules per child of add:
//   - <entry name="..."> elements match a base entry of the same element
//     name AND the same name attribute; matched entries merge recursively,
//     unmatched entries are appended (so named collections union, with
//     base's fields winning inside a shared entry).
//   - Repeated non-entry elements (e.g. <member> lists) are treated as an
//     atomic group: if base defines ANY child of that element name, base's
//     group wins outright and add's is ignored.
//   - Singleton elements merge recursively; leaf text in base wins.
func Overlay(base, add *Node) {
	if base == nil || add == nil {
		return
	}
	// Index base children: entries by (name, name-attr); others by name.
	type key struct{ name, attr string }
	entries := map[key]*Node{}
	baseHas := map[string]int{} // child name -> count in base BEFORE merging
	var single map[string]*Node
	for _, c := range base.Children {
		if a := c.Attr("name"); a != "" {
			entries[key{c.Name, a}] = c
		}
		baseHas[c.Name]++
		if single == nil {
			single = map[string]*Node{}
		}
		single[c.Name] = c
	}

	for _, ac := range add.Children {
		if a := ac.Attr("name"); a != "" {
			if bc, ok := entries[key{ac.Name, a}]; ok {
				Overlay(bc, ac)
				continue
			}
			cp := ac.Clone()
			base.Children = append(base.Children, cp)
			entries[key{ac.Name, a}] = cp
			continue
		}
		switch {
		case baseHas[ac.Name] == 0:
			// Base never defined this element: inherit add's, including
			// every member of a repeated group.
			base.Children = append(base.Children, ac.Clone())
		case baseHas[ac.Name] == 1 && countByName(add, ac.Name) == 1:
			// True singletons on both sides merge recursively.
			Overlay(single[ac.Name], ac)
		default:
			// Repeated groups (member lists): base's group wins atomically.
		}
	}
	if base.Text == "" && len(base.Children) == 0 {
		base.Text = add.Text
	}
}

func countByName(n *Node, name string) int {
	c := 0
	for _, ch := range n.Children {
		if ch.Name == name {
			c++
		}
	}
	return c
}

// Clone deep-copies the node.
func (n *Node) Clone() *Node {
	if n == nil {
		return nil
	}
	cp := &Node{Name: n.Name, Text: n.Text}
	if n.Attrs != nil {
		cp.Attrs = make(map[string]string, len(n.Attrs))
		for k, v := range n.Attrs {
			cp.Attrs[k] = v
		}
	}
	cp.Children = make([]*Node, len(n.Children))
	for i, c := range n.Children {
		cp.Children[i] = c.Clone()
	}
	return cp
}
