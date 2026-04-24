package main

import (
	"flag"
	"log"
	"path/filepath"

	"c2/hashgen"
)

func main() {
	out := flag.String("out", "../beacon/include", "output directory for api_hashes.h")
	flag.Parse()
	clean := filepath.Clean(*out)
	if err := hashgen.Generate(clean); err != nil {
		log.Fatalf("gen_hashes: %v", err)
	}
	log.Printf("wrote api_hashes.h to %s", clean)
}
