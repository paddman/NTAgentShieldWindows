//go:build !linux

package main

import "fmt"

func main() { fmt.Println("ntagentshield-doctor is a Linux-only command") }
