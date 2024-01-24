package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
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

type Request struct {
	opcode  uint16
	file    *os.File
	blksize uint64
	timeout uint64
	oack    []byte
}

// | Opcode (2 bytes) |  ErrorCode (2 bytes) |   ErrMsg   |   0  |
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

func createErrorPacket(errorCode uint16, msg string) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf[0:2], uint16(OpCodeERROR))
	binary.BigEndian.PutUint16(buf[2:4], errorCode)
	buf = fmt.Appendf(buf, msg)
	buf = append(buf, 0)
	return buf
}

func appendOption(buf []byte, key string, val uint64) []byte {
	buf = fmt.Append(buf, key)
	buf = append(buf, 0)
	buf = fmt.Append(buf, val)
	buf = append(buf, 0)
	return buf
}

func parseOptions(req *Request, tokens [][]byte) ([]byte, error) {
	var oack []byte

	req.blksize = 512
	req.timeout = 3

	for i := 0; i < len(tokens); i += 2 {

		uintval, err := strconv.ParseUint(string(tokens[i+1]), 10, 64)
		if err != nil {
			return nil, err
		}

		switch string(tokens[i]) {
		case "blksize":
			req.blksize = uintval
			oack = appendOption(oack, "blksize", req.blksize)

		case "tsize":
			if info, err := req.file.Stat(); err != nil {
				return nil, fmt.Errorf("cannot stat() file %s. err: %s", req.file.Name(), err)
			} else {
				oack = appendOption(oack, "tsize", uint64(info.Size()))
			}
		case "timeout":
			req.timeout = uintval
			oack = appendOption(oack, "timeout", req.timeout)
		default:
			_ = fmt.Errorf("unknown option [%s]", tokens[i])
		}
	}

	return oack, nil
}

func parseFilenameMode(tokens [][]byte) (*Request, error) {

	var err error
	var req = &Request{}

	filename := string(tokens[0])
	req.file, err = os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("cannot open file %s. err: %s", filename, err)
	}

	if string(tokens[1]) != "octet" {
		return nil, fmt.Errorf("only mode [octet] is supported")
	}

	return req, nil
}

func parseRequest(buf []byte) (*Request, error) {
	if len(buf) < 9 {
		return nil, fmt.Errorf("req is only %d bytes. minimun len 9", len(buf))
	}
	if buf[len(buf)-1] != 0 {
		return nil, fmt.Errorf("req does not end with a zero byte. last byte is [%x]. bytes[%x]", buf[len(buf)-1], buf)
	}
	if opcode := binary.BigEndian.Uint16(buf[0:2]); opcode != 1 {
		return nil, fmt.Errorf("this server only supports READ")
	}

	tokens := bytes.Split(buf[2:len(buf)-1], []byte{0})

	if len(tokens) < 2 {
		return nil, fmt.Errorf("there should be at least 2 fields. filename and mode. found fields: %d", len(tokens))
	} else if (len(tokens) % 2) != 0 {
		return nil, fmt.Errorf("uneven number of fields. found fields: %d", len(tokens))
	}

	req, err := parseFilenameMode(tokens)
	if err != nil {
		return nil, err
	}

	if oack, err := parseOptions(req, tokens[2:]); err != nil {
		return nil, err
	} else {
		req.oack = oack
	}

	return req, nil
}

func sendBlockWaitForAck(data []byte, conn *net.UDPConn, blocknumber uint16) error {
	_, err := conn.Write(data)
	if err != nil {
		return fmt.Errorf("cannot write to client [%s]. err: [%s]", conn.RemoteAddr(), err)
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	socketBytesRead, err := conn.Read(data)
	if err != nil {
		return fmt.Errorf("read from socket: [%s]", err)
	} else if socketBytesRead < 4 {
		return fmt.Errorf("client response is only %d bytes long. should be 4 at least 4 (ACK)", socketBytesRead)
	}

	if answerOpcode := binary.BigEndian.Uint16(data[0:2]); OpCode(answerOpcode) == OpCodeERROR {
		clientErrCode, clientErrMessage := parseClientError(data[2:socketBytesRead])
		return fmt.Errorf("client interupted the transfer with OpCode ERROR (%d). code %d, message %s", answerOpcode, clientErrCode, clientErrMessage)
	} else if OpCode(answerOpcode) != OpCodeACK {
		return fmt.Errorf("unexpected opcode from client during transmission %d", answerOpcode)
	} else if ackedBlocknumber := binary.BigEndian.Uint16(data[2:4]); ackedBlocknumber != blocknumber {
		return fmt.Errorf("client ACKed block %d. but should be %d", ackedBlocknumber, blocknumber)
	}

	return nil
}

func sendFile(req *Request, conn *net.UDPConn) error {

	rdr := bufio.NewReader(req.file)
	data := make([]byte, 4+req.blksize)

	var blocknumber uint16 = 1
	for {
		binary.BigEndian.PutUint16(data[0:2], 3)
		binary.BigEndian.PutUint16(data[2:4], uint16(blocknumber))

		fileBytesRead, err := rdr.Read(data[4 : 4+req.blksize])
		if err != nil {
			return fmt.Errorf("reading from filename [%s]. err: [%s]", req.file.Name(), err)
		}

		err = sendBlockWaitForAck(data[0:4+fileBytesRead], conn, blocknumber)
		if err != nil {
			return err
		}

		if fileBytesRead < int(req.blksize) {
			break
		}

		blocknumber = blocknumber + 1
	}
	return nil
}

func handleRequest(request []byte, conn *net.UDPConn) error {

	req, err := parseRequest(request)
	if err != nil {
		return err
	}
	defer req.file.Close()

	fmt.Printf("%s filename [%s]\n", conn.RemoteAddr(), req.file.Name())
	if req.oack != nil {
		err = sendBlockWaitForAck(req.oack, conn, 0)
		if err != nil {
			return err
		}
	}

	return sendFile(req, conn)
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
			conn.Write(createErrorPacket(99, err.Error()))
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
