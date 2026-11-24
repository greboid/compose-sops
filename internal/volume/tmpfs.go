package volume

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const tmpfsFlags = unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC

// Tmpfs mounts each volume as its own size-limited tmpfs. It needs
// CAP_SYS_ADMIN.
type Tmpfs struct{}

// Mount mounts a tmpfs at dir, excluded from swap where the kernel supports
// it (Linux 6.4+).
func (Tmpfs) Mount(dir string, size, inodes int) error {
	data := fmt.Sprintf("mode=0711,size=%d,nr_inodes=%d", size, inodes)
	err := unix.Mount("tmpfs", dir, "tmpfs", tmpfsFlags, data+",noswap")
	if errors.Is(err, unix.EINVAL) {
		err = unix.Mount("tmpfs", dir, "tmpfs", tmpfsFlags, data)
	}
	if err != nil {
		return fmt.Errorf("cannot mount tmpfs at %s: %w", dir, err)
	}
	return nil
}

// Seal remounts the tmpfs at dir read-only.
func (Tmpfs) Seal(dir string) error {
	if err := unix.Mount("", dir, "", unix.MS_REMOUNT|unix.MS_RDONLY|tmpfsFlags, ""); err != nil {
		return fmt.Errorf("cannot remount %s read-only: %w", dir, err)
	}
	return nil
}

// Unmount unmounts dir, detaching it if it is still busy.
func (Tmpfs) Unmount(dir string) error {
	err := unix.Unmount(dir, unix.UMOUNT_NOFOLLOW)
	if errors.Is(err, unix.EBUSY) {
		err = unix.Unmount(dir, unix.UMOUNT_NOFOLLOW|unix.MNT_DETACH)
	}
	if err != nil {
		return fmt.Errorf("cannot unmount %s: %w", dir, err)
	}
	return nil
}

// Mounted reports whether dir is a mount point in /proc/self/mountinfo.
func (Tmpfs) Mounted(dir string) (bool, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return false, fmt.Errorf("cannot read mount table: %w", err)
	}
	defer f.Close()
	dir = filepath.Clean(dir)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 4 && unescapeMountPath(fields[4]) == dir {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("cannot parse mount table: %w", err)
	}
	return false, nil
}

// unescapeMountPath decodes the octal escapes (\040 etc.) used in mountinfo.
func unescapeMountPath(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
