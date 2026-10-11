package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func TestLogoName(t *testing.T) {
	tests := []struct {
		ids  []string
		want string
	}{
		{[]string{"arch"}, "arch"},
		{[]string{"ubuntu", "debian"}, "ubuntu"}, // most specific first
		{[]string{"debian"}, "debian"},
		{[]string{"manjaro", "arch"}, "arch"}, // derivative uses its parent's logo
		{[]string{"fedora"}, "fedora"},
		{[]string{"rhel", "fedora"}, "fedora"},
		{[]string{"plan9"}, "tux"},
		{[]string{"tux"}, "tux"},
		{nil, "tux"},
	}
	for _, tt := range tests {
		if got := logoName(tt.ids); got != tt.want {
			t.Errorf("logoName(%v) = %s, want %s", tt.ids, got, tt.want)
		}
	}
}

func TestEveryLogoHasColorAndSaneSize(t *testing.T) {
	for name, art := range logos {
		if _, ok := logoColors[name]; !ok {
			t.Errorf("%s has no color", name)
		}
		if len(art) < 5 || len(art) > 8 {
			t.Errorf("%s has %d lines", name, len(art))
		}
		for i, l := range art {
			if w := lipgloss.Width(l); w > 14 {
				t.Errorf("%s line %d is %d wide", name, i, w)
			}
		}
	}
}

func TestWideViewShowsLogoWhenTallEnough(t *testing.T) {
	m := finish(t, newModel(t, fakeHost(t))) // fakeHost is Ubuntu
	tall := resize(m, 140, 40).View()
	if !strings.Contains(tall, "(o)") {
		t.Errorf("expected the Ubuntu logo:\n%s", tall)
	}
	if !strings.Contains(tall, "/100") {
		t.Error("score must still be shown next to the logo")
	}
	if short := resize(m, 140, 20).View(); strings.Contains(short, "(o)") {
		t.Error("logo must be hidden when there's no vertical room")
	}
	if narrow := resize(m, 80, 40).View(); strings.Contains(narrow, "(o)") {
		t.Error("logo must be hidden in the stacked layout")
	}
}
