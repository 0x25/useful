package main

//golang code to read file and search with regex
// with goroutine

import (
	"bufio"
	"fmt"
	"os"
	"flag"
	"time"
	"regexp"
)

type search struct {
	out *os.File
	pattern  string
	outName string
}

func routine(config search, word string, sem chan bool, sync chan bool) {

	defer func() { <-sem }()
	
	fmt.Println("debug: ",word)

	match, _ := regexp.MatchString(config.pattern, word)
	if match {
		if config.outName != "" {
			for{
				fmt.Println("for ",word)
				if len(sync) == 0{
					sync <- true
					config.out.WriteString(word+"\n")
					<-sync
					break
				}
			}

		} else{
		fmt.Println(word)
		}
	}
}


func main() {
	regexPtr := flag.String("r","","regex")
	threadPtr := flag.Int("t",10,"Number of concurrente process to calculate hashes")
	filePtr := flag.String("f","","wordlist file (one word/line)")
	outPtr := flag.String("o","","output filename")
	flag.Parse()

	if *regexPtr == "" {
		fmt.Println("Need to enter a regex")
		os.Exit(1)
	}
	if *filePtr == "" {
		fmt.Println("Need to set a wordlist file")
		os.Exit(2)
	}

	fmt.Println("start")

	file, err := os.Open(*filePtr)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	config := search{pattern:*regexPtr , outName: *outPtr}

	if config.outName == "" {
		fmt.Println("no output file")
	} else{
		outFile, err := os.OpenFile(*outPtr,os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			fmt.Println("Error create file ",err)
			os.Exit(3)
		}
		config.out = outFile
		defer outFile.Close()
	}

	fmt.Println("search : ", config.pattern)
	concurrency := *threadPtr
	fmt.Println("concurrency goroutine: ", concurrency)
	sem := make(chan bool, concurrency)
	sync := make(chan bool, 1)

	fileScanner := bufio.NewScanner(file)

	for fileScanner.Scan() {
		sem <- true
		go routine(config,fileScanner.Text(), sem, sync)
	}

	//wait sem to be empty before continue/quite
	for {
		if len(sem) == 0 {
			break
		}
		time.Sleep(1 * time.Millisecond)
	}

	fmt.Println("done")
}
