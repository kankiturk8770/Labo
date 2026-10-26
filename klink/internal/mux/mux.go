package mux

import (
	"encoding/binary"
	"errors"
)

const (
	CmdSYN  byte = 0x01
	CmdDATA byte = 0x02
	CmdFIN  byte = 0x03
)

type Frame struct {
	StreamID uint32
	Cmd      byte
	Payload  []byte
}

func EncodeFrame(f *Frame) []byte {
	buf := make([]byte, 7+len(f.Payload))
	binary.BigEndian.PutUint32(buf[0:4], f.StreamID)
	buf[4] = f.Cmd
	binary.BigEndian.PutUint16(buf[5:7], uint16(len(f.Payload)))
	copy(buf[7:], f.Payload)
	return buf
}

func DecodeFrame(data []byte) (*Frame, error) {
	if len(data) < 7 {
		return nil, errors.New("mux frame too short")
	}
	streamID := binary.BigEndian.Uint32(data[0:4])
	cmd := data[4]
	length := int(binary.BigEndian.Uint16(data[5:7]))
	if len(data) < 7+length {
		return nil, errors.New("mux payload incomplete")
	}
	return &Frame{
		StreamID: streamID,
		Cmd:      cmd,
		Payload:  data[7 : 7+length],
	}, nil
}
