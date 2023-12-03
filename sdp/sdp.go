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

// Session Description Protocol Library
//
// This is the stuff people embed in SIP packets that tells you how to
// establish audio and/or video sessions.
//
// Here's a typical SDP for a phone call sent by Asterisk:
//
//   v=0
//   o=root 31589 31589 IN IP4 10.0.0.38
//   s=session
//   c=IN IP4 10.0.0.38                <-- ip we should connect to
//   t=0 0
//   m=audio 30126 RTP/AVP 0 101       <-- audio port number and codecs
//   a=rtpmap:0 PCMU/8000              <-- use μ-Law codec at 8000 hz
//   a=rtpmap:101 telephone-event/8000 <-- they support rfc2833 dtmf tones
//   a=fmtp:101 0-16
//   a=silenceSupp:off - - - -         <-- they'll freak out if you use VAD
//   a=ptime:20                        <-- send packet every 20 milliseconds
//   a=sendrecv                        <-- they wanna send and receive audio
//
// Here's an SDP response from MetaSwitch, meaning the exact same
// thing as above, but omitting fields we're smart enough to assume:
//
//   v=0
//   o=- 3366701332 3366701332 IN IP4 1.2.3.4
//   s=-
//   c=IN IP4 1.2.3.4
//   t=0 0
//   m=audio 32898 RTP/AVP 0 101
//   a=rtpmap:101 telephone-event/8000
//   a=ptime:20
//
// If you wanted to go where no woman or man has gone before in the
// voip world, like stream 44.1khz stereo MP3 audio over a IPv6 TCP
// socket for a Flash player to connect to, you could do something
// like:
//
//   v=0
//   o=- 3366701332 3366701332 IN IP6 dead:beef::666
//   s=-
//   c=IN IP6 dead:beef::666
//   t=0 0
//   m=audio 80 TCP/IP 111
//   a=rtpmap:111 MP3/44100/2
//   a=sendonly
//
// Reference Material:
//
// - SDP RFC: http://tools.ietf.org/html/rfc4566
// - SIP/SDP Handshake RFC: http://tools.ietf.org/html/rfc3264
//

package sdp

import (
	"bytes"
	"errors"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/deolan/gosip/util"
)

const (
	ContentType = "application/sdp"
	MaxLength   = 1450
	MediaLineStateNone = 0
	MediaLineStateAudio = 1	
	MediaLineStateVideo = 2
)

// SDP represents a Session Description Protocol SIP payload.
type SDP struct {
	Origin   Origin      // This must always be present
	Addr     string      // Connect to this IP; never blank (from c=)
	Audio    *Media      // Non-nil if we can establish audio
	Video    *Media      // Non-nil if we can establish video
	Session  string      // s= Session Name (default "-")
	Time     string      // t= Active Time (default "0 0")
	Ptime    int         // Transmit frame every N milliseconds (default 20)
	SendOnly bool        // True if 'a=sendonly' was specified in SDP
	RecvOnly bool        // True if 'a=recvonly' was specified in SDP
	Inactive bool        // True if 'a=inactive' was specified in SDP
	Fprint  *Fingerprint // Fingerprint
	IceUfrag string 	 // ICE Ufag
	IcePwd 	 string 	 // ICE password
	IceOnly  bool        // ICE trickle sdpfrag
	Rtcp     *Rtcp       // RTCP
	RtcpMux bool         // RTCP MUX attribute
	Group    *Group      // Group bundle
	SetupRole string 	 // Setup attribute
	Candidates []Candidate // ICE candidates
	Ssrcs []Ssrc 		 // SSRC
	Attrs    [][2]string // a= lines we don't recognize
	Other    [][2]string // Other description
}

// Easy way to create a basic, everyday SDP for VoIP.
func New(addr *net.UDPAddr, codecs ...Codec) *SDP {
	sdp := new(SDP)
	sdp.Addr = addr.IP.String()
	sdp.Origin.ID = util.GenerateOriginID()
	sdp.Origin.Version = sdp.Origin.ID
	sdp.Origin.Addr = sdp.Addr
	sdp.Audio = new(Media)
	sdp.Audio.Proto = "RTP/AVP"
	sdp.Audio.Port = uint16(addr.Port)
	sdp.Audio.Codecs = make([]Codec, len(codecs))
	for i := 0; i < len(codecs); i++ {
		sdp.Audio.Codecs[i] = codecs[i]
	}
	sdp.Attrs = make([][2]string, 0, 8)
	return sdp
}

// parses sdp message text into a happy data structure
func Parse(s string) (sdp *SDP, err error) {
	sdp = new(SDP)
	sdp.Session = "pokémon"
	sdp.Time = "0 0"

	// Eat version.
	if !strings.HasPrefix(s, "v=0\r\n") {
		return nil, errors.New("sdp must start with v=0\\r\\n")
	}
	s = s[5:]

	// Turn into lines.
	lines := strings.Split(s, "\r\n")
	if lines == nil || len(lines) < 2 {
		return nil, errors.New("too few lines in sdp")
	}

	// We abstract the structure of the media lines so we need a place to store
	// them before assembling the audio/video data structures.
	var audioinfo, videoinfo string
	artpmaps := make([]string, len(lines))
	artpmapcnt := 0
	afmtps := make([]string, len(lines))
	afmtpcnt := 0

	vrtpmaps := make([]string, len(lines))
	vrtpmapcnt := 0
	vfmtps := make([]string, len(lines))
	vfmtpcnt := 0
	sdp.Attrs = make([][2]string, 0, len(lines))

	medialinestate := MediaLineStateNone

	// Extract information from SDP.
	var okOrigin, okConn bool
	for _, line := range lines {
		switch {
		case line == "":
			continue
		case len(line) < 3 || line[1] != '=': // empty or invalid line
			log.Println("Bad line in SDP:", line)
			continue
		case line[0] == 'm': // media line
			line = line[2:]
			if strings.HasPrefix(line, "audio ") {
				audioinfo = line[6:]
				medialinestate = MediaLineStateAudio
			} else if strings.HasPrefix(line, "video ") {
				videoinfo = line[6:]
				medialinestate = MediaLineStateVideo
			} else {
				log.Println("Unsupported SDP media line:", line)
			}
		case line[0] == 's': // session line
			sdp.Session = line[2:]
		case line[0] == 't': // active time
			sdp.Time = line[2:]
		case line[0] == 'c': // connect to this ip address
			if okConn {
				log.Println("Dropping extra c= line in sdp:", line)
				continue
			}
			sdp.Addr, err = parseConnLine(line)
			if err != nil {
				return nil, err
			}
			okConn = true
		case line[0] == 'o': // origin line
			err = parseOriginLine(&sdp.Origin, line)
			if err != nil {
				return nil, err
			}
			okOrigin = true
		case line[0] == 'a': // attribute lines
			line = line[2:]
			switch {
			case strings.HasPrefix(line, "rtpmap:"):
				switch medialinestate {
					case MediaLineStateNone:
						log.Println("Skipping rtpmap: ", line)
					case MediaLineStateAudio:
						artpmaps[artpmapcnt] = line[7:]
						artpmapcnt++
					case MediaLineStateVideo:
						vrtpmaps[vrtpmapcnt] = line[7:]
						vrtpmapcnt++
				}
			case strings.HasPrefix(line, "fmtp:"):
				switch medialinestate {
					case MediaLineStateNone:
						log.Println("Skipping rtpmap: ", line)
					case MediaLineStateAudio:
						afmtps[afmtpcnt] = line[5:]
						afmtpcnt++
					case MediaLineStateVideo:
						vfmtps[vfmtpcnt] = line[5:]
						vfmtpcnt++
				}
			case strings.HasPrefix(line, "ptime:"):
				ptimeS := line[6:]
				if ptime, err := strconv.Atoi(ptimeS); err == nil && ptime > 0 {
					sdp.Ptime = ptime
				} else {
					log.Println("Invalid SDP Ptime value", ptimeS)
				}
			case strings.HasPrefix(line, "fingerprint:"):
				toks := strings.Split(line[12:], " ")
				if toks == nil || len(toks) != 2 {
					log.Println("Invalid SDP Fingerprint value")
				} else {
					sdp.Fprint = new(Fingerprint)
					sdp.Fprint.HashFunc = toks[0]
					sdp.Fprint.Fingerprint = toks[1]					
				}
			case strings.HasPrefix(line, "ice-pwd:"):
				sdp.IcePwd = line[8:]
			case strings.HasPrefix(line, "ice-ufrag:"):
				sdp.IceUfrag = line[10:]
			case strings.HasPrefix(line, "candidate:"):
				toks := strings.Split(line[10:], " ")
				if toks == nil {
					log.Println("Invalid SDP Candidate value")
				} else {
					var candidate Candidate
					candidate.Foundation = toks[0]
					candidate.ComponentId = toks[1]
					candidate.Transport = toks[2]
					if priority, err := strconv.Atoi(toks[3]); err!= nil {
						log.Println("Invalid SDP Candidate priority value")
					} else {
						candidate.Priority = priority
					}
 					candidate.ConnectionAddress = toks[4]
					if port, err := strconv.Atoi(toks[5]); err!= nil {
						log.Println("Invalid SDP Candidate port value")
					} else {
						candidate.Port = port
					}
 					if len(toks) >= 8 && toks[6] == "typ" {
 						candidate.CandType = toks[7]
 					}
 					if len(toks) >= 10 && toks[8] == "raddr" {
 						candidate.RelAddr = toks[9]
 					}
  					if len(toks) >= 12 && toks[10] == "rport" {
						if relPort, err := strconv.Atoi(toks[11]); err != nil {
							log.Println("Invalid SDP Candidate relport value")
						} else {
							candidate.RelPort = relPort
						}
 					}
 					sdp.Candidates = append(sdp.Candidates, candidate)
				}
			case strings.HasPrefix(line, "ssrc:"):
				toks := strings.Split(line[5:], ":")
				if toks == nil {
					toks1 := strings.Split(line[5:], " ")
					if toks1 == nil {
						log.Println("Invalid SDP SSRC value")
					} else {
						var ssrc Ssrc
						if len(toks1) >= 1 {
							ssrc.Id = toks1[0]
						}
						if len(toks1) >= 2 {
							ssrc.Attribute = toks1[1]
						}
						sdp.Ssrcs = append(sdp.Ssrcs, ssrc)
					}
				} else {
					toks1 := strings.Split(toks[0], " ")
					if toks1 == nil {
						log.Println("Invalid SDP SSRC value")
					} else {
						var ssrc Ssrc
						if len(toks1) >= 1 {
							ssrc.Id = toks1[0]
						}
						if len(toks1) >= 2 {
							ssrc.Attribute = toks1[1]
						}
						if len(toks) >= 2 {						
							ssrc.Value = toks[1]
						}	 
						sdp.Ssrcs = append(sdp.Ssrcs, ssrc)
					}
				}
			case strings.HasPrefix(line, "rtcp:"):
				toks := strings.Split(line[5:], " ")
				if toks == nil {
					log.Println("Invalid SDP RTCP value")
				} else {
					var rtcp Rtcp
					if len(toks) >= 2 {
						rtcp.Nettype = toks[1]
					}
					if len(toks) >= 3 {
						rtcp.Addrtype = toks[2]
					}
					if len(toks) >= 4 {
						rtcp.ConnectionAddress = toks[3]
					}
					if len(toks) >= 1 {
						if port, err := strconv.Atoi(toks[0]); err != nil {
							log.Println("Invalid SDP RTCP port value")
						} else {
							rtcp.Port = uint16(port)
							sdp.Rtcp = &rtcp
						}		
					}		
				}
			case strings.HasPrefix(line, "group:"):
				toks := strings.Split(line[6:], " ")
				if toks == nil || len(toks) < 2 {
					log.Println("Invalid SDP Group value")
				} else {
					sdp.Group = new(Group)
					sdp.Group.Semantics = toks[0]
					for i := 1; i < len(toks); i++ {
						sdp.Group.IdentificationTag = append(sdp.Group.IdentificationTag, toks[i])
					}
				}
			case strings.HasPrefix(line, "setup:"):
				sdp.SetupRole = line[6:]									
			case line == "rtcp-mux":
				sdp.RtcpMux = true
			case line == "sendrecv":
			case line == "sendonly":
				sdp.SendOnly = true
			case line == "recvonly":
				sdp.RecvOnly = true
			case line == "inactive":
				sdp.Inactive = true
			default:
				if n := strings.Index(line, ":"); n >= 0 {
					if n == 0 {
						log.Println("Evil SDP attribute:", line)
					} else {
						l := len(sdp.Attrs)
						sdp.Attrs = sdp.Attrs[0 : l+1]
						sdp.Attrs[l] = [2]string{line[0:n], line[n+1:]}
					}
				} else {
					l := len(sdp.Attrs)
					sdp.Attrs = sdp.Attrs[0 : l+1]
					sdp.Attrs[l] = [2]string{line, ""}
				}
			}
		default:

			// Other unknown fields will be saved here
			if n := strings.Index(line, "="); n >= 0 {

				if n == 0 {
					log.Println("Evil SDP field:", line)
				} else {
					sdp.Other = append(sdp.Other, [2]string{line[0:n], line[n+1:]})
				}
			} else {
				sdp.Other = append(sdp.Other, [2]string{line, ""})
			}
		}
	}

	artpmaps = artpmaps[0:artpmapcnt]
	afmtps = afmtps[0:afmtpcnt]
	vrtpmaps = vrtpmaps[0:vrtpmapcnt]
	vfmtps = vfmtps[0:vfmtpcnt]

	if !okConn || !okOrigin {
		return nil, errors.New("sdp missing mandatory information")
	}

	// Assemble audio/video information.
	var pts []uint8

	if audioinfo != "" {
		sdp.Audio = new(Media)
		sdp.Audio.Port, sdp.Audio.Proto, pts, err = parseMediaInfo(audioinfo)
		if err != nil {
			return nil, err
		}
		err = populateCodecs(sdp.Audio, pts, artpmaps, afmtps)
		if err != nil {
			return nil, err
		}
	} else {
		 // sdp.Video = nil
	}

	if videoinfo != "" {

		sdp.Video = new(Media)
		sdp.Video.Port, sdp.Video.Proto, pts, err = parseMediaInfo(videoinfo)
		if err != nil {
			return nil, err
		}
		err = populateCodecs(sdp.Video, pts, vrtpmaps, vfmtps)
		if err != nil {
			return nil, err
		}
	} else {
		 // sdp.Video = nil
	}

	if sdp.Audio == nil && sdp.Video == nil {
		return nil, errors.New("sdp has no audio or video information")
	}

	return sdp, nil
}

func (sdp *SDP) ContentType() string {
	return ContentType
}

func (sdp *SDP) Data() []byte {
	if sdp == nil {
		return nil
	}
	var b bytes.Buffer
	sdp.Append(&b)
	return b.Bytes()
}

func (sdp *SDP) String() string {
	if sdp == nil {
		return ""
	}
	var b bytes.Buffer
	sdp.Append(&b)
	return b.String()
}

func (sdp *SDP) Append(b *bytes.Buffer) {
	if !sdp.IceOnly {
		b.WriteString("v=0\r\n")
		sdp.Origin.Append(b)
		b.WriteString("s=")
		if sdp.Session == "" {
			b.WriteString("-")
		} else {
			b.WriteString(sdp.Session)
		}
		b.WriteString("\r\n")
		if util.IsIPv6(sdp.Addr) {
			b.WriteString("c=IN IP6 ")
		} else {
			b.WriteString("c=IN IP4 ")
		}
		if sdp.Addr == "" {
			b.WriteString("0.0.0.0")
		} else {
			b.WriteString(sdp.Addr)
		}
		b.WriteString("\r\n")
		b.WriteString("t=")
		if sdp.Time == "" {
			b.WriteString("0 0")
		} else {
			b.WriteString(sdp.Time)
		}
		b.WriteString("\r\n")
	}
	if sdp.Audio != nil {
		sdp.Audio.Append("audio", b)
	}
	if sdp.Video != nil {
		sdp.Video.Append("video", b)
	}
	for _, attr := range sdp.Attrs {
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
	if sdp.Ptime > 0 {
		b.WriteString("a=ptime:")
		b.WriteString(strconv.Itoa(sdp.Ptime))
		b.WriteString("\r\n")
	}
	if sdp.Fprint != nil {
		sdp.Fprint.Append(b)
	}
	if sdp.IcePwd == "" {
	} else {
		b.WriteString("a=ice-pwd:")
		b.WriteString(sdp.IcePwd)
		b.WriteString("\r\n")		
	}
	if sdp.IceUfrag == "" {
	} else {
		b.WriteString("a=ice-ufrag:")
		b.WriteString(sdp.IceUfrag)
		b.WriteString("\r\n")		
	}
	for i, _ := range sdp.Candidates {
		sdp.Candidates[i].Append(b)
	}
	for i, _ := range sdp.Ssrcs {
		sdp.Ssrcs[i].Append(b)
	}
	if sdp.Group != nil {
		sdp.Group.Append(b)
	}
	if sdp.SetupRole == "" {
	} else {
		b.WriteString("a=setup:")
		b.WriteString(sdp.SetupRole)
		b.WriteString("\r\n")		
	}
	if !sdp.IceOnly {
		if sdp.SendOnly {
			b.WriteString("a=sendonly\r\n")
		} else if sdp.RecvOnly {
			b.WriteString("a=recvonly\r\n")
		} else if sdp.Inactive {
			b.WriteString("a=inactive\r\n")
		} else {
			b.WriteString("a=sendrecv\r\n")
		}
	}
	if sdp.RtcpMux {
		b.WriteString("a=rtcp-mux\r\n")
	}
	if sdp.Rtcp != nil {
		sdp.Rtcp.Append(b)
	}
	// save unknown field
	if sdp.Other != nil {
		for _, v := range sdp.Other {
			b.WriteString(v[0])
			b.WriteString("=")
			b.WriteString(v[1])
			b.WriteString("\r\n")
		}
	}
}

// Here we take the list of payload types from the m= line (e.g. 9 18 0 101)
// and turn them into a list of codecs.
//
// If we couldn't find a matching rtpmap, iana standardized will be filled in
// like magic.
func populateCodecs(media *Media, pts []uint8, rtpmaps []string, fmtps []string) (err error) {
	media.Codecs = make([]Codec, len(pts))
	for n, pt := range pts {
		codec := &media.Codecs[n]
		codec.PT = pt
		prefix := strconv.FormatInt(int64(pt), 10) + " "
		for _, rtpmap := range rtpmaps {
			if strings.HasPrefix(rtpmap, prefix) {
				err = parseRtpmapInfo(codec, rtpmap[len(prefix):])
				if err != nil {
					return err
				}
				break
			}
		}
		if codec.Name == "" {
			if isDynamicPT(pt) {
				return errors.New("dynamic codec missing rtpmap")
			} else {
				if v, ok := StandardCodecs[pt]; ok {
					*codec = v
				} else {
					return errors.New("unknown iana codec id: " +
						strconv.Itoa(int(pt)))
				}
			}
		}
		for _, fmtp := range fmtps {
			if strings.HasPrefix(fmtp, prefix) {
				codec.Fmtp = fmtp[len(prefix):]
				break
			}
		}
	}
	return nil
}

// Returns true if IANA says this payload type is dynamic.
func isDynamicPT(pt uint8) bool {
	return (pt >= 96)
}

// Give me the part of the a=rtpmap line that looks like: "PCMU/8000" or
// "L16/16000/2".
func parseRtpmapInfo(codec *Codec, s string) (err error) {
	toks := strings.Split(s, "/")
	if toks != nil && len(toks) >= 2 {
		codec.Name = toks[0]
		codec.Rate, err = strconv.Atoi(toks[1])
		if err != nil {
			return errors.New("invalid rtpmap rate")
		}
		if len(toks) >= 3 {
			codec.Param = toks[2]
		}
	} else {
		return errors.New("invalid rtpmap")
	}
	return nil
}

// Give me the part of an "m=" line that looks like: "30126 RTP/AVP 0 101".
func parseMediaInfo(s string) (port uint16, proto string, pts []uint8, err error) {
	toks := strings.Split(s, " ")
	if toks == nil || len(toks) < 3 {
		return 0, "", nil, errors.New("invalid m= line")
	}

	// We don't care if they say like "666/2" which is a weird way of saying hey!
	// send ME rtcp too (I think).
	portS := toks[0]
	if n := strings.Index(portS, "/"); n > 0 {
		portS = portS[0:n]
	}

	// Convert port to int and check range.
	portU, err := strconv.ParseUint(portS, 10, 16)
	if err != nil || !(0 <= port && port <= 65535) {
		return 0, "", nil, errors.New("invalid m= port")
	}
	port = uint16(portU)

	// Is it rtp? srtp? udp? tcp? etc. (must be 3+ chars)
	proto = toks[1]

	// The rest of these tokens are payload types sorted by preference.
	pts = make([]uint8, len(toks)-2)
	for n, pt := range toks[2:] {
		pt, err := strconv.ParseUint(pt, 10, 8)
		if err != nil {
			return 0, "", nil, errors.New("invalid pt in m= line")
		}
		pts[n] = byte(pt)
	}

	return port, proto, pts, nil
}

// I want a string that looks like "c=IN IP4 10.0.0.38".
func parseConnLine(line string) (addr string, err error) {
	toks := strings.Split(line[2:], " ")
	if toks == nil || len(toks) != 3 {
		return "", errors.New("invalid conn line")
	}
	if toks[0] != "IN" || (toks[1] != "IP4" && toks[1] != "IP6") {
		return "", errors.New("unsupported conn net type")
	}
	addr = toks[2]
	if n := strings.Index(addr, "/"); n >= 0 {
		return "", errors.New("multicast address in c= line D:")
	}
	return addr, nil
}

// I want a string that looks like "o=root 31589 31589 IN IP4 10.0.0.38".
func parseOriginLine(origin *Origin, line string) error {
	toks := strings.Split(line[2:], " ")
	if toks == nil || len(toks) != 6 {
		return errors.New("invalid origin line")
	}
	if toks[3] != "IN" || (toks[4] != "IP4" && toks[4] != "IP6") {
		return errors.New("unsupported origin net type")
	}
	origin.User = toks[0]
	origin.ID = toks[1]
	origin.Version = toks[2]
	origin.Addr = toks[5]
	if n := strings.Index(origin.Addr, "/"); n >= 0 {
		return errors.New("multicast address in o= line D:")
	}
	return nil
}
