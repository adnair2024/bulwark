package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var logos = map[string][]string{
	"arch": {
		`     /\     `,
		`    /  \    `,
		`   /    \   `,
		`  /  ,,  \  `,
		` /  |  |  \ `,
		`/_-''  ''-_\`,
	},
	"ubuntu": {
		`    .--.    `,
		`  (o)  '-.  `,
		` .'      _) `,
		` '.   .-'   `,
		`  (o)  .-.  `,
		`    '--'    `,
	},
	"debian": {
		`   .-==-.   `,
		`  /  ,-. \  `,
		` |  (   _/  `,
		`  \  '-.    `,
		`   '.       `,
		`     '-._   `,
	},
	"fedora": {
		`   .-----.  `,
		`  /  ,--. \ `,
		` |  _| (_/ |`,
		` | |_  |   |`,
		`  \  \_/   / `,
		`   '-----'  `,
	},
	"tux": {
		`    .--.    `,
		`   |o_o |   `,
		`   |:_/ |   `,
		`  //   \ \  `,
		` (|     | ) `,
		`/'\_   _/'\ `,
		`\___)=(___/ `,
	},
}

// logoName picks a logo from os-release IDs (ID first, then ID_LIKE), so a
// derivative such as Manjaro gets its parent's logo. Unknown distros get Tux.
func logoName(ids []string) string {
	for _, id := range ids {
		if _, ok := logos[id]; ok && id != "tux" {
			return id
		}
	}
	return "tux"
}

func logoArt(ids []string) []string { return logos[logoName(ids)] }

// renderLogo returns the colored logo as an even-width block.
func renderLogo(ids []string) string {
	style := lipgloss.NewStyle().Foreground(logoColors[logoName(ids)])
	return style.Render(strings.Join(logoArt(ids), "\n"))
}
