// teamserver/cmd/gen_obf/main.go
package main

import (
	"flag"
	"log"
	"path/filepath"

	"c2/obfgen"
)

func main() {
	host := flag.String("host", "127.0.0.1", "server host to embed in beacon")
	out  := flag.String("out", "../beacon/include", "output directory for obf_strings.h")
	flag.Parse()

	if err := obfgen.Generate(*host, filepath.Clean(*out)); err != nil {
		log.Fatalf("gen_obf: %v", err)
	}
	log.Printf("wrote obf_strings.h to %s (host=%s)", filepath.Clean(*out), *host)
}
