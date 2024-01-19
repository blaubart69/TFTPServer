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

	fmt.Printf("filename [%s], mode [%s]\n", filename, mode)

	f, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("cannot open file. err: %s", err)
	}
	defer f.Close()

	var blksize = 512
	var blocknumber = 1
	rdr := bufio.NewReader(f)
	buf = append(buf)

	for {
		buf = buf[0 : 4+blksize]
		binary.BigEndian.PutUint16(buf[0:2], 3)
		binary.BigEndian.PutUint16(buf[2:4], uint16(blocknumber))

		fileBytesRead, err := rdr.Read(buf[4 : 4+blksize])
		if err != nil {
			return fmt.Errorf("reading from filename [%s]. err: [%s]", filename, err)
		}

		sentBytes, err := conn.Write(buf[0 : 4+fileBytesRead])
		if err != nil {
			return fmt.Errorf("cannot write to client [%s]. err: [%s]", conn.RemoteAddr(), err)
		}

		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		socketBytesRead, err := conn.Read(buf)
		if err != nil {
			return fmt.Errorf("client response: [%s]", err)
		} else if socketBytesRead < 4 {
			return fmt.Errorf("client response is only %d bytes long. should be 4.", socketBytesRead)
		}

		if answerOpcode := binary.BigEndian.Uint16(buf[0:2]); answerOpcode != 4 {
			return fmt.Errorf("client answered with opcode %d", answerOpcode)
		}

		if ackedBlocknumber := binary.BigEndian.Uint16(buf[2:4]); ackedBlocknumber != ackedBlocknumber {
			return fmt.Errorf("client ACKed block %d. but should be %d", ackedBlocknumber, blocknumber)
		}

		fmt.Printf("block: %d, sent %d bytes to %s\n", blocknumber, sentBytes, conn.RemoteAddr())

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
		fmt.Printf("could not create socket to client (%s). err: [%s]\n", client, err)
	} else {
		err := handleRequest(buf, conn)
		if err != nil {
			fmt.Printf("error handling client (%s). err: [%s]\n", client, err)
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
		buf := make([]byte, 64)
		bytesReceived, addr, err := conn.ReadFromUDP(buf[0:])
		if err != nil {
			fmt.Println(err)
		} else {
			go mainRequest(buf[:bytesReceived], addr)
		}
	}
}
