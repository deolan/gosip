// Copyright 2020 Justine Alexandra Roberts Tunney
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sdp

import (
	"bytes"
	"strconv"
	"strings"
)

// Media is a high level representation of the c=/m=/a= lines for describing a
// specific type of media. Only "audio" and "video" are supported at this time.
type Media struct {
	Proto  string  // RTP, SRTP, UDP, UDPTL, TCP, TLS, etc.
	Port   uint16  // Port number (0 - 2^16-1)
	Codecs []Codec // Collection of codecs of a specific type.
	SendOnly bool        // True if 'a=sendonly' was specified in SDP
	RecvOnly bool        // True if 'a=recvonly' was specified in SDP
	Inactive bool        // True if 'a=inactive' was specified in SDP
	Fprint  *Fingerprint // Fingerprint
	IceUfrag string 	 // ICE Ufag
	IcePwd 	 string 	 // ICE password
	IceOnly  bool        // ICE trickle sdpfrag
	SetupRole string 	 // Setup attribute
	Candidates []Candidate // ICE candidates
	Rtcp     *Rtcp       // RTCP
	RtcpMux bool         // RTCP MUX attribute
	Ssrcs []Ssrc 		 // SSRC
	Attrs    [][2]string // a= lines we don't recognize
}

func (media *Media) Append(type_ string, b *bytes.Buffer) {
	b.WriteString("m=")
	b.WriteString(type_)
	b.WriteString(" ")
	b.WriteString(strconv.FormatUint(uint64(media.Port), 10))
	b.WriteString(" ")
	if media.Proto == "" {
		b.WriteString("RTP/AVP")
	} else {
		b.WriteString(media.Proto)
	}
	for _, codec := range media.Codecs {
		b.WriteString(" ")
		b.WriteString(strconv.FormatInt(int64(codec.PT), 10))
	}
	b.WriteString("\r\n")
	for _, codec := range media.Codecs {
		codec.Append(b)
	}
	if media.Fprint != nil {
		media.Fprint.Append(b)
	}
	if media.IcePwd == "" {
	} else {
		b.WriteString("a=ice-pwd:")
		b.WriteString(media.IcePwd)
		b.WriteString("\r\n")		
	}
	if media.IceUfrag == "" {
	} else {
		b.WriteString("a=ice-ufrag:")
		b.WriteString(media.IceUfrag)
		b.WriteString("\r\n")		
	}
	for i, _ := range media.Candidates {
		media.Candidates[i].Append(b)
	}
	for i, _ := range media.Ssrcs {
		media.Ssrcs[i].Append(b)
	}
	if media.SetupRole == "" {
	} else {
		b.WriteString("a=setup:")
		b.WriteString(media.SetupRole)
		b.WriteString("\r\n")		
	}
	if !media.IceOnly {
		if media.SendOnly {
			b.WriteString("a=sendonly\r\n")
		} else if media.RecvOnly {
			b.WriteString("a=recvonly\r\n")
		} else if media.Inactive {
			b.WriteString("a=inactive\r\n")
		} else {
			b.WriteString("a=sendrecv\r\n")
		}
	}
	if media.RtcpMux {
		b.WriteString("a=rtcp-mux\r\n")
	}
	if media.Rtcp != nil {
		media.Rtcp.Append(b)
	}
	for _, attr := range media.Attrs {
		if attr[1] == "" {
			b.WriteString("a=")
			b.WriteString(attr[0])
			b.WriteString("\r\n")
		} else {
			b.WriteString("a=")
			b.WriteString(attr[0])
			b.WriteString(":")
			b.WriteString(attr[1])
			b.WriteString("\r\n")
		}
	}
}

func (media *Media) RemoveCodec(name string) bool {
	dId := -1
	for i, codec := range media.Codecs {
		if strings.EqualFold(codec.Name, name) {
			dId = i
		}
	}
	if dId != -1 {
		media.Codecs[dId] = media.Codecs[len(media.Codecs)-1]
    	media.Codecs = media.Codecs[:len(media.Codecs)-1]
    	return true
	} else {
		return false
	}
}

func (media *Media) RemoveCodecWithRate(name string, rate int) bool {
	dId := -1
	for i, codec := range media.Codecs {
		if strings.EqualFold(codec.Name, name) && codec.Rate == rate {
			dId = i
		}
	}
	if dId != -1 {
		media.Codecs[dId] = media.Codecs[len(media.Codecs)-1]
    	media.Codecs = media.Codecs[:len(media.Codecs)-1]
    	return true
	} else {
		return false
	}
}
