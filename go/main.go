package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
)

func handleRequest(buf []byte, client *net.UDPAddr) {
	fmt.Printf("> recv from: %s (%d bytes)\n", client.String(), len(buf))

	if len(buf) < 9 {
		fmt.Printf("req is only %d bytes. minimun len 9", len(buf))
	} else if buf[len(buf)-1] != 0 {
		fmt.Printf("req does not end with a zero byte. last byte is [%x]. bytes[%x]", buf[len(buf)-1], buf)
	} else if opcode := binary.BigEndian.Uint16(buf[0:2]); opcode != 1 {
		fmt.Print("this server only supports READ")
	} else {
		tokens := bytes.Split(buf[2:len(buf)-1], []byte{0})
		filename := string(tokens[0])
		mode := string(tokens[1])

		fmt.Printf("filename [%s], mode [%s]", filename, mode)
	}
}

func main() {

	udpAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:6969")

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("listening on: %s\n", udpAddr.String())
	conn, err := net.ListenUDP("udp", udpAddr)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for {
		//var buf [512]byte
		buf := make([]byte, 1024)
		bytesReceived, addr, err := conn.ReadFromUDP(buf[0:])
		if err != nil {
			fmt.Println(err)
		} else {
			go handleRequest(buf[:bytesReceived], addr)
		}
	}
}
