// Package dashboard serves the real-time web UI for monitoring events,
// managing agents, reviewing quarantine items, and configuring policies.
package dashboard

import (
	"fmt"
	"html/template"
	"sync/atomic"
)

// Pastel palette — soft tones that work on dark backgrounds without eye strain.
var avatarPalette = [...]string{
	"#7ec8e3", // sky blue
	"#a78bda", // lavender
	"#c9a9e0", // soft purple
	"#e8a0bf", // dusty rose
	"#f4b183", // peach
	"#b5d99c", // sage green
	"#8cc5b2", // mint
	"#d6c28e", // warm sand
}

var avatarSeq uint64

// agentAvatar returns an inline SVG avatar deterministically generated from the agent name.
// All avatars use a 40×40 viewBox scaled to the requested display size.
func agentAvatar(name string, size int) template.HTML {
	if name == "" {
		return ""
	}
	h := fnv32a(name)
	uid := fmt.Sprintf("av%d", atomic.AddUint64(&avatarSeq, 1))

	pl := uint32(len(avatarPalette))
	i1 := h % pl
	i2 := (h / pl) % pl
	if i2 == i1 {
		i2 = (i2 + 1) % pl
	}
	i3 := (h / pl / pl) % pl
	if i3 == i1 || i3 == i2 {
		i3 = (i3 + 2) % pl
	}
	c1, c2, c3 := avatarPalette[i1], avatarPalette[i2], avatarPalette[i3]

	var body string
	switch (h >> 16) % 8 {
	case 0: // radial gradient
		body = `<defs><radialGradient id="` + uid + `">` +
			`<stop offset="0%" stop-color="` + c1 + `"/>` +
			`<stop offset="100%" stop-color="` + c2 + `"/>` +
			`</radialGradient></defs>` +
			`<circle cx="20" cy="20" r="20" fill="url(#` + uid + `)"/>`

	case 1: // pixel 4×4
		body = `<clipPath id="` + uid + `"><circle cx="20" cy="20" r="20"/></clipPath>` +
			`<g clip-path="url(#` + uid + `)">`
		colors := [4]string{c1, c2, c3, c1}
		for row := 0; row < 4; row++ {
			for col := 0; col < 4; col++ {
				ci := (h >> uint(row*4+col)) & 3
				body += fmt.Sprintf(`<rect x="%d" y="%d" width="11" height="11" fill="%s"/>`,
					col*10, row*10, colors[ci])
			}
		}
		body += `</g>`

	case 2: // concentric rings
		body = `<circle cx="20" cy="20" r="20" fill="` + c1 + `"/>` +
			`<circle cx="20" cy="20" r="13" fill="` + c2 + `"/>` +
			`<circle cx="20" cy="20" r="7" fill="` + c3 + `"/>`

	case 3: // eclipse
		body = `<defs><radialGradient id="` + uid + `">` +
			`<stop offset="0%" stop-color="` + c3 + `"/>` +
			`<stop offset="40%" stop-color="` + c3 + `"/>` +
			`<stop offset="70%" stop-color="` + c1 + `"/>` +
			`<stop offset="100%" stop-color="` + c2 + `"/>` +
			`</radialGradient></defs>` +
			`<circle cx="20" cy="20" r="20" fill="url(#` + uid + `)"/>`

	case 4: // diagonal band
		body = `<defs><clipPath id="` + uid + `"><circle cx="20" cy="20" r="20"/></clipPath></defs>` +
			`<circle cx="20" cy="20" r="20" fill="` + c1 + `"/>` +
			`<line x1="-2" y1="28" x2="42" y2="12" stroke="` + c2 + `" stroke-width="6" clip-path="url(#` + uid + `)" opacity="0.6"/>`

	case 5: // quadrants
		body = `<defs><clipPath id="` + uid + `"><circle cx="20" cy="20" r="20"/></clipPath></defs>` +
			`<g clip-path="url(#` + uid + `)">` +
			`<rect x="0" y="0" width="20" height="20" fill="` + c1 + `"/>` +
			`<rect x="20" y="0" width="20" height="20" fill="` + c2 + `"/>` +
			`<rect x="0" y="20" width="20" height="20" fill="` + c3 + `"/>` +
			`<rect x="20" y="20" width="20" height="20" fill="` + c1 + `"/>` +
			`</g>`

	case 6: // horizontal stripe
		body = `<defs><clipPath id="` + uid + `"><circle cx="20" cy="20" r="20"/></clipPath></defs>` +
			`<circle cx="20" cy="20" r="20" fill="` + c1 + `"/>` +
			`<rect x="0" y="14" width="40" height="12" fill="` + c2 + `" clip-path="url(#` + uid + `)" opacity="0.55"/>`

	case 7: // nebula (offset radial)
		cx := 30 + (h>>20)%40
		cy := 30 + (h>>24)%40
		body = fmt.Sprintf(
			`<defs><radialGradient id="%s" cx="%d%%" cy="%d%%">`+
				`<stop offset="0%%" stop-color="%s"/>`+
				`<stop offset="50%%" stop-color="%s"/>`+
				`<stop offset="100%%" stop-color="%s"/>`+
				`</radialGradient></defs>`+
				`<circle cx="20" cy="20" r="20" fill="url(#%s)"/>`,
			uid, cx, cy, c1, c2, c3, uid)
	}

	return template.HTML(fmt.Sprintf(
		`<svg class="avatar" width="%d" height="%d" viewBox="0 0 40 40">%s</svg>`,
		size, size, body))
}

// agentCell returns avatar + name wrapped for table cell display.
func agentCell(name string) template.HTML {
	if name == "" {
		return ""
	}
	return template.HTML(fmt.Sprintf(
		`<span class="agent-cell">%s %s</span>`,
		agentAvatar(name, 20), template.HTMLEscapeString(name)))
}

// fnv32a implements FNV-1a hash. Matches the JS mirror in layoutFoot.
func fnv32a(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}
