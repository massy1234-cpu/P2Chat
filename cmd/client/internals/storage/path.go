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


// get the current directory and go up until there is the file 'go.mod' so the root directory of the project
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

