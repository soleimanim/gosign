package cliargs

import "os"

func IsDebugMode() bool {
	args := os.Args[1:]
	for _, a := range args {
		if a == "-d" || a == "--debug" {
			return true
		}
	}

	return false
}
