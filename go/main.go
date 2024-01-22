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

type OpCode uint16

const (
	OpCodeREAD  OpCode = 1
	OpCodeWRITE OpCode = 2
	OpCodeDATA  OpCode = 3
	OpCodeACK   OpCode = 4
	OpCodeERROR OpCode = 5
	OpCodeOACK  OpCode = 6
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

/*
2 bytes     2 bytes      string    1 byte

	-----------------------------------------

| Opcode |  ErrorCode |   ErrMsg   |   0  |

	-----------------------------------------
	       Figure 5-4: ERROR packet
*/
func parseClientError(data []byte) (uint16, string) {
	var clientErrCode = binary.BigEndian.Uint16(data[0:2])

	var clientErrMessage string
	if len(data) < 4 {
		clientErrMessage = "packet does not contain valid error message"
	} else {
		clientErrMessage = string(data[2 : len(data)-1])
	}

	return clientErrCode, clientErrMessage
}

func sendFile(f *os.File, conn *net.UDPConn) error {
	var blksize = 512
	var blocknumber uint16 = 1
	rdr := bufio.NewReader(f)
	data := make([]byte, 4+blksize)

	for {
		binary.BigEndian.PutUint16(data[0:2], 3)
		binary.BigEndian.PutUint16(data[2:4], uint16(blocknumber))

		fileBytesRead, err := rdr.Read(data[4 : 4+blksize])
		if err != nil {
			return fmt.Errorf("reading from filename [%s]. err: [%s]", f.Name(), err)
		}

		_, err = conn.Write(data[0 : 4+fileBytesRead])
		if err != nil {
			return fmt.Errorf("cannot write to client [%s]. err: [%s]", conn.RemoteAddr(), err)
		}

		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		socketBytesRead, err := conn.Read(data)
		if err != nil {
			return fmt.Errorf("read from socket: [%s]", err)
		} else if socketBytesRead < 4 {
			return fmt.Errorf("client response is only %d bytes long. should be 4 at least 4 (ACK).", socketBytesRead)
		}

		if answerOpcode := binary.BigEndian.Uint16(data[0:2]); OpCode(answerOpcode) == OpCodeERROR {
			clientErrCode, clientErrMessage := parseClientError(data[2:socketBytesRead])
			return fmt.Errorf("client interupted the transfer with OpCode ERROR (%d). code %d, message %s", answerOpcode, clientErrCode, clientErrMessage)
		} else if OpCode(answerOpcode) != OpCodeACK {
			return fmt.Errorf("unexpected opcode from client during transmission %d", answerOpcode)
		} else if ackedBlocknumber := binary.BigEndian.Uint16(data[2:4]); ackedBlocknumber != blocknumber {
			return fmt.Errorf("client ACKed block %d. but should be %d", ackedBlocknumber, blocknumber)
		}

		if fileBytesRead < blksize {
			break
		}

		blocknumber = blocknumber + 1
	}
	return nil
}

func handleRequest(request []byte, conn *net.UDPConn) error {

	err := parseRequest(request)
	if err != nil {
		return err
	}

	tokens := bytes.Split(request[2:len(request)-1], []byte{0})
	filename := string(tokens[0])
	mode := string(tokens[1])

	fmt.Printf("%s filename [%s], mode [%s]\n", conn.RemoteAddr(), filename, mode)

	f, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("cannot open file. err: %s", err)
	}
	defer f.Close()

	return sendFile(f, conn)
}

func mainRequest(buf []byte, client *net.UDPAddr) {

	//fmt.Printf("> recv from: %s (%d bytes)\n", client.String(), len(buf))

	conn, err := net.DialUDP("udp", nil, client)
	if err != nil {
		fmt.Printf("could not create socket to client (%s). err: [%s]\n", client, err)
	} else {
		defer conn.Close()

		err := handleRequest(buf, conn)
		if err != nil {
			fmt.Printf("%s error in transfer. err: [%s]\n", client, err)
		} else {
			fmt.Printf("%s transfer finished ok\n", client)
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
