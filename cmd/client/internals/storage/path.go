package storage

import (
	"os"
	"path/filepath"
)

var BasePath string
var ProjectRoot string

func init() {
	ProjectRoot = projectRoot()
	BasePath = filepath.Join(ProjectRoot, "data")
}

func projectRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}

