package main

//golang code to crack md5
// with goroutine
// to do : add hash algo

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"time"
	"flag"
)

func GetMD5Hash(text string, hash string, sem chan bool) {

	defer func() { <-sem }()

	h := md5.Sum([]byte(text))
	res := hex.EncodeToString(h[:])
	//fmt.Println(text," ",res, " ", hash)
	//time.Sleep(1 * time.Second)
	if res == hash {
		fmt.Println(text)
		os.Exit(0)
	}
}


func main() {
	hashPtr := flag.String("m","","Md5 hash value")
	threadPtr := flag.Int("t",10,"Number of concurrente process to calculate hashes")
	filePtr := flag.String("f","","Dictionnary file (one word/line)")
	flag.Parse()

	if *hashPtr == "" {
		fmt.Println("Need to enter a md5 hash")
		os.Exit(1)
	}
	if *filePtr == "" {
		fmt.Println("Need to set a dictionnary file")
		os.Exit(2)
	}

	fmt.Println("start")
	start := time.Now()
	hash := *hashPtr


	file, err := os.Open(*filePtr)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	fmt.Println("try to crack : " + hash)
	concurrency := *threadPtr
	fmt.Println("concurrency goroutine: ", concurrency)
	sem := make(chan bool, concurrency)

	fileScanner := bufio.NewScanner(file)

	for fileScanner.Scan() {
		sem <- true
		go GetMD5Hash(fileScanner.Text(), hash, sem)
	}

	//wait sem to be empty before continue/quite
	for {
		if len(sem) == 0 {
			break
		}
		time.Sleep(1 * time.Millisecond)
	}

	fmt.Println("done")
	elapsed := time.Since(start)
	fmt.Println("crack took ", elapsed)
}
