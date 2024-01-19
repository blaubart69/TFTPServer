package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"
)

func parseRequest(buf []byte) error {
	if len(buf) < 9 {
		return fmt.Errorf("req is only %d bytes. minimun len 9", len(buf))
	}
	if buf[len(buf)-1] != 0 {
		return fmt.Errorf("req does not end with a zero byte. last byte is [%x]. bytes[%x]", buf[len(buf)-1], buf)
	}
	if opcode := binary.BigEndian.Uint16(buf[0:2]); opcode != 1 {
		return fmt.Errorf("this server only supports READ")
	}

	return nil
}

func handleRequest(buf []byte, conn *net.UDPConn) error {

	err := parseRequest(buf)
	if err != nil {
		return err
	}

	tokens := bytes.Split(buf[2:len(buf)-1], []byte{0})
	filename := string(tokens[0])
	mode := string(tokens[1])

	fmt.Printf("filename [%s], mode [%s]", filename, mode)

	f, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("cannot open file. err: %s", err)
	}
	defer f.Close()

	var blksize = 512
	var blocknumber = 1
	rdr := bufio.NewReader(f)

	for {
		binary.BigEndian.PutUint16(buf[0:2], 3)
		binary.BigEndian.PutUint16(buf[2:4], uint16(blocknumber))

		fileBytesRead, errRead := rdr.Read(buf[4 : 4+blksize])
		if errRead != nil {
			return fmt.Errorf("error reading from filename [%s]. err: [%s]", filename, errRead)
		}

		_, errWrite := conn.Write(buf)
		if errWrite != nil {
			return fmt.Errorf("cannot write to client [%s]. err: [%s]", conn.RemoteAddr(), errWrite)
		}

		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		socketBytesRead, err := conn.Read(buf)

		if fileBytesRead < blksize {
			break
		}

		blocknumber = blocknumber + 1
	}

	return nil
}

func mainRequest(buf []byte, client *net.UDPAddr) {

	fmt.Printf("> recv from: %s (%d bytes)\n", client.String(), len(buf))

	conn, err := net.DialUDP("udp", nil, client)
	if err != nil {
		fmt.Printf("could not create socket to client (%s). err: [%s]", client, err)
	} else {
		_, err := handleRequest(buf, conn)
		if err != nil {
			fmt.Printf("error handling client (%s). err: [%s]", client, err)
		}
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
		buf := make([]byte, 2048)
		bytesReceived, addr, err := conn.ReadFromUDP(buf[0:])
		if err != nil {
			fmt.Println(err)
		} else {
			go mainRequest(buf[:bytesReceived], addr)
		}
	}
}
