package provider

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// mountInfoPath describes the host mount table on Linux.
const mountInfoPath = "/proc/self/mountinfo"

// requireTmpfs verifies that path lives on a tmpfs filesystem by finding the
// longest mount point in /proc/self/mountinfo that contains it.
func requireTmpfs(path string) error {
	f, err := os.Open(mountInfoPath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", mountInfoPath, err)
	}
	defer f.Close()

	best := ""
	bestType := ""
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, " ")
		sep := -1
		for i, field := range fields {
			if field == "-" {
				sep = i
				break
			}
		}
		if sep < 5 || len(fields) < sep+3 {
			continue
		}
		mountPoint := fields[4]
		fstype := fields[sep+1]
		if !pathContains(mountPoint, path) {
			continue
		}
		if len(mountPoint) > len(best) {
			best = mountPoint
			bestType = fstype
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("cannot parse %s: %w", mountInfoPath, err)
	}
	if best == "" {
		return fmt.Errorf("cannot determine the filesystem backing %s", path)
	}
	if bestType != "tmpfs" {
		return fmt.Errorf("runtime dir %s is on a %q filesystem; compose-sops requires tmpfs (plaintext must never touch a persistent disk)", path, bestType)
	}
	return nil
}

// pathContains reports whether outer is path or an ancestor directory of it.
// Both paths must be cleaned and absolute.
func pathContains(outer, path string) bool {
	if outer == path {
		return true
	}
	if outer == "/" {
		return true
	}
	return strings.HasPrefix(path, outer+"/")
}
