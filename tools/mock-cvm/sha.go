package main

import (
	"crypto/sha512"
	"hash"
)

func sha512New() hash.Hash { return sha512.New() }
