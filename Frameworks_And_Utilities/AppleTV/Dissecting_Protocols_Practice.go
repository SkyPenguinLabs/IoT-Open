package main

/*

This program is to represent the dissection of the BPLIST file format and dissecting files with go, this was made as a security example or research 

example to better dissect and understand how the protocols such as AirTunes, AirPlay, and DAAP/DMAP/DACP work from the outside or rather externally.

This program takes advantage of ECP API endpoints on the servers on a given AppleTV to check and parse values such as verify BPLIST headers or to 

also pick apart and detect codes within the server's DAAP response. Apple seems to like to hide these codes such as merr,mstt,mlog etc, so this program 

dissects those codes and compares them to their unique messages and what they are used for. 

This program is only an example to show how you can externally research a system without fully working with the internals or making packets or listening
for specific function calls

*/


import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

// File names
const (
	DAAP_SERVER_FILE    = "daap_server_response"
	AirPlay_Server_File = "airplay_server_response.bplist"
)

/*

6d6c6964
6d737474
6d657272
6d657273
6d6c6f67
*/
// Variables
var (
	MERR            = []byte{0x6d, 0x65, 0x72, 0x72}
	MSTT            = []byte{0x6d, 0x73, 0x74, 0x74}
	MERS            = []byte{0x6d, 0x65, 0x72, 0x73}
	MLOG            = []byte{0x6d, 0x6c, 0x6f, 0x67}
	MLID            = []byte{0x6d, 0x6c, 0x69, 0x64}
	BPLIST_DATA_TAG = "application/x-apple-binary-plist"
	DMAPP_TAGGED    = "application/x-dmap-tagged"
)

// Digital Audio Control Protocol codes from our previous files
var CodeMessageMap = map[string]string{
	"mstt": "[+]: Found server status code at index [IDX=%s]",
	"merr": "[!]: Found DAAP server error code at index [IDX=%s]",
	"mers": "[!]: Found DAAP server media message at index[IDX=%s]",
	"mlog": "[!]: Found DAAP server login response message at index[IDX=%s]",
	"mlid": "[!]: Found DAAP server login attempt ID at index[IDX=%s]",
}

// Run function based on headers of responses
var RequestHeadResp = map[string]func(filename string){
	BPLIST_DATA_TAG: func(f string) {
		fmt.Println("[Info] Found binary plist response -> ", BPLIST_DATA_TAG)
		data, x := os.Open(f)
		CheckErr(x)
		defer data.Close()
		Reader := Pre_Process_File(data)
		ValidateFile(Reader)
	},
	DMAPP_TAGGED: func(f string) {
		fmt.Println("[Info] Found DMAP tagged response  -> ", DMAPP_TAGGED)
		Data, x := os.Open(f)
		CheckErr(x)
		defer Data.Close()
		stats, x := Data.Stat()
		CheckErr(x)
		size := stats.Size()
		b := make([]byte, size)
		buffer := bufio.NewReader(Data)
		if _, x = buffer.Read(b); x != nil {
			fmt.Println("Failed to read buffer -> ", x)
		}
		if idx := SearchByteListIDX(b, MSTT); idx != -1 {
			fmt.Println(
				fmt.Sprintf(CodeMessageMap[string(MSTT)], fmt.Sprint(idx)),
			)
		}
		if idx := SearchByteListIDX(b, MERR); idx != -1 {
			fmt.Println(
				fmt.Sprintf(CodeMessageMap[string(MERR)], fmt.Sprint(idx)),
			)
		}
		if idx := SearchByteListIDX(b, MERS); idx != -1 {
			fmt.Println(
				fmt.Sprintf(CodeMessageMap[string(MERS)], fmt.Sprint(idx)),
			)
		}
		if idx := SearchByteListIDX(b, MLOG); idx != -1 {
			fmt.Println(
				fmt.Sprintf(CodeMessageMap[string(MLOG)], fmt.Sprint(idx)),
			)
		}
		if idx := SearchByteListIDX(b, MLID); idx != -1 {
			fmt.Println(
				fmt.Sprintf(CodeMessageMap[string(MLID)], fmt.Sprint(idx)),
			)
		}
	},
}

// Check the error
func CheckErr(x error) {
	if x != nil {
		log.Fatal(x)
	}
}

// Sub functions

// Search for bytes in a byte array
func SearchByteListIDX(byter, sequence []byte) int {
	for idx := 0; idx < len(byter); idx++ {
		if len(byter)-idx >= len(sequence) && bytes.Equal(byter[idx:idx+len(sequence)], sequence) {
			return idx
		}
	}
	return -1
}

//Make request
func Make_GET_Compare_Content_Types(url, expected string) ([]byte, bool) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	req, x := http.NewRequest("GET", url, nil)
	CheckErr(x)
	res, x := client.Do(req)
	CheckErr(x)
	fmt.Println("[+] User Agent -> ", res.Request.UserAgent())
	defer res.Body.Close()
	content_type := res.Header[http.CanonicalHeaderKey("content-type")]
	if content_type != nil {
		if content_type[0] == expected {
			write_body, x := ioutil.ReadAll(res.Body)
			CheckErr(x)
			return write_body, true
		} else {
			fmt.Println("Content type empty? -> ", content_type, " match = ", expected)
			fmt.Println(res.StatusCode)
			return nil, false
		}
	} else {
		fmt.Println("[!] Error: Could not output or check content type due to connection erorrs, content-type was NULL ")
		return nil, false
	}
}

// Process the BPLIST file if there was one.
func Pre_Process_File(Data *os.File) *bytes.Reader {
	stats, x := Data.Stat()
	CheckErr(x)
	size := stats.Size()
	b := make([]byte, size)
	buffer := bufio.NewReader(Data)
	if _, x = buffer.Read(b); x != nil {
		fmt.Println("Failed to read buffer -> ", x)
	}
	bufferreader := bytes.NewReader(b)
	return bufferreader
}

// Validate the BPLIST header
func ValidateFile(byter *bytes.Reader) {
	var head uint64
	if x := binary.Read(byter, binary.BigEndian, &head); x != nil {
		log.Fatal(x)
	}
	bytearray := make([]byte, 8)
	binary.BigEndian.PutUint64(bytearray, head)
	fmt.Println("BPLIST ARRAY -> ", bytearray)
	if string(bytearray) == "bplist00" {
		fmt.Println("[+] BPLIST has been found -> ", string(bytearray))
		fmt.Println("[+] Magic bytes           -> ", bytearray)
	}
}

func main() {
	host := os.Args[1]
	if bod, x := Make_GET_Compare_Content_Types(fmt.Sprintf("http://%s:3689/login?attempt=1", host), DMAPP_TAGGED); x {
		ioutil.WriteFile(DAAP_SERVER_FILE, bod, 0600)
		RequestHeadResp[DMAPP_TAGGED](DAAP_SERVER_FILE)
	}
	if bod, x := Make_GET_Compare_Content_Types(fmt.Sprintf("http://%s:7000/info", host), BPLIST_DATA_TAG); x {
		ioutil.WriteFile(AirPlay_Server_File, bod, 0600)
		RequestHeadResp[BPLIST_DATA_TAG](AirPlay_Server_File)
	}
}
