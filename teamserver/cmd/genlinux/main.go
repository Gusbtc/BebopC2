package main

import (
	"c2/obfgen"
	"fmt"
	"os"
)

func main() {
	outDir := "../../beacon-linux/include"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}
	if err := obfgen.Generate("127.0.0.1", outDir, "linux"); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("obf_strings.h generated for Linux")
}
