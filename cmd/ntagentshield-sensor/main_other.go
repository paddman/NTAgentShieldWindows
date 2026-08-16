//go:build !linux

package main

import "fmt"

func main() { fmt.Println("ntagentshield-sensor is a Linux-only helper") }
