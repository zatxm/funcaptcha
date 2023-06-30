package main

import "time"

func main() {
	// timestamp: 1688131156885
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)
	println(timestamp)
}
