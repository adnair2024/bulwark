package audit

import (
	"io/fs"
	"syscall"
)

func uidOf(fi fs.FileInfo) uint32 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Uid
	}
	return 0
}
