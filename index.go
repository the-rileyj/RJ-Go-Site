package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	//"encoding/base64"

	//"image/png"

	"github.com/gorilla/websocket"
	"github.com/olahol/melody"
	mailgun "gopkg.in/mailgun/mailgun-go.v1"
)

//Notes:
//Fix IP log
//Influences From:

//Function for determining which snapcode will show on the template
func getSnap() string {
	if rand.Intn(2) == 1 {
		return "snapcode_cash"
	} else {
		return "snapcode_casher"
	}
}

// isPrivateSubnet - check to see if this ip is in a private subnet
func isPrivateSubnet(ipAddress net.IP) bool {
	// my use case is only concerned with ipv4 atm
	if ipCheck := ipAddress.To4(); ipCheck != nil {
		// iterate over all our ranges
		for _, r := range privateRanges {
			// check if this ip is in a private range
			if inRange(r, ipAddress) {
				return true
			}
		}
	}
	return false
}

func getIPAdress(r *http.Request) string {
	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip"} {
		addresses := strings.Split(r.Header.Get(h), ",")
		// march from right to left until we get a public address
		// that will be the address right before our proxy.
		for i := len(addresses) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(addresses[i])
			// header can contain spaces too, strip those out.
			realIP := net.ParseIP(ip)
			if !realIP.IsGlobalUnicast() || isPrivateSubnet(realIP) {
				// bad address, go to next
				continue
			}
			return ip
		}
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if aip := net.ParseIP(ip); aip != nil && err == nil {
		if aip.IsGlobalUnicast() && !isPrivateSubnet(aip) {
			return aip.String()
		}
	}
	return ""
}

func writeStructToJson(strct interface{}, path string) {
	res, err := json.Marshal(strct)
	if err != nil {
		println(err)
		return
	}
	err = ioutil.WriteFile(path, res, 0644)
}

func (vT *visiTracker) InSlice(a string) bool {
	for _, b := range vT.IPList {
		if b == a {
			return true
		}
	}
	return false
}

func getIter() []int {
	return make([]int, 1000)
}

func (vT *visiTracker) swapViews() visiTracker {
	return visiTracker{vT.GspinV, vT.Uv, vT.V, vT.IPList}
}

func herdSpin(w http.ResponseWriter, r *http.Request) {
	err := tpl.ExecuteTemplate(w, "herdspin.gohtml", vT)
	if err != nil {
		print(err)
	}
}

func chat(w http.ResponseWriter, r *http.Request){
	err := tpl.ExecuteTemplate(w, "chat.gohtml", vT)
	if err != nil {
		print(err)
	}
}

func spy(w http.ResponseWriter, r *http.Request) {
	mux.Lock()
	lImg := spyImg
	mux.Unlock()
	tpl.ExecuteTemplate(w, "spy.gohtml", base64.StdEncoding.EncodeToString(lImg))
}

func spyer(w http.ResponseWriter, r *http.Request) {
	conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
	if err != nil {
		fmt.Println(err)
	}
	mux.Lock()
	gconn = conn
	mux.Unlock()
	if _, ok := err.(websocket.HandshakeError); ok {
		fmt.Println("Not a websocket handshake")
		return
	} else if err != nil {
		log.Printf("%s\nError in establishing WS with spyer\n", err)
		return
	}
	for {
		_, p, err := conn.ReadMessage()
		if err != nil {
			return
		}
		mux.Lock()
		spyImg = p
		mux.Unlock()
	}
}

func spying(w http.ResponseWriter, r *http.Request) {
	conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)

}

func sms(w http.ResponseWriter, r *http.Request) {
	fmt.Println(1, r.URL.Query()["AccountSid"])
	fmt.Println(2, r.URL.Query()["accountsid"])
}

func serveFile(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "rjResume.pdf") {
		addr := getIPAdress(r)
		mux.Lock()
		seen := resumeRequesters[addr]
		resumeRequesters[addr]++
		myEmail := mEmail
		lmg := mg
		mux.Unlock()
		if seen == 0 {
			_, _, err := lmg.Send(mailgun.NewMessage("robot@mail.therileyjohnson.com", fmt.Sprintf("Someone at %s Downloaded Your Resume", addr), "See the title dummy", myEmail))
			if err != nil {
				fmt.Println("Error sending email to yourself")
			}
		}
	}
	http.ServeFile(w, r, "./static"+r.URL.Path)
}

func index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query()["check"] == nil {
		mux.Lock()
		vT.V++
		if getIPAdress(r) != "" && !vT.InSlice(getIPAdress(r)) {
			vT.Uv++
			vT.IPList = append(vT.IPList, getIPAdress(r))
		}
		mux.Unlock()
		go writeStructToJson(vT, "../numer.json")
	}

	err := tpl.ExecuteTemplate(w, "index.gohtml", vT)
	if err != nil {
		print(err)
	}
}

//This, isPrivateSubnet, getIPAdress, and ipRange are from: https://husobee.github.io/golang/ip-address/2015/12/17/remote-ip-go.html
//inRange - check to see if a given ip address is within a range given
func inRange(r ipRange, ipAddress net.IP) bool {
	// strcmp type byte comparison
	if bytes.Compare(ipAddress, r.start) >= 0 && bytes.Compare(ipAddress, r.end) < 0 {
		return true
	}
	return false
}

//ipRange - a structure that holds the start and end of a range of ip addresses
type ipRange struct {
	start net.IP
	end   net.IP
}

type visiTracker struct {
	V      int      `json:"numb"`
	Uv     int      `json:"uniq"`
	GspinV int      `json:"gnumb"`
	IPList []string `json:"ips"`
}

//Struct to hold the private and public keys for the MailGun API
type info struct {
	Private    string `json:"private"`
	Public     string `json:"public"`
	MailServer string `json:"mailServer"`
	MyEmail    string `json:"myEmail"`
	Spyl       string `json:"spyLogin"`
	Spyp       string `json:"spyPass"`
	GPass      string `json:"gPass"`
	Sid        string `json:"sid"`
	Token      string `json:"token"`
	Number     string `json:"number"`
	LyricKey   string `json:"lyric_key"`
	Production bool   `json:"production"`
	ProPort    string `json:"pro-port"`
	DevPort    string `json:"dev-port"`
}

var privateRanges = []ipRange{
	{
		start: net.ParseIP("10.0.0.0"),
		end:   net.ParseIP("10.255.255.255"),
	},
	{
		start: net.ParseIP("100.64.0.0"),
		end:   net.ParseIP("100.127.255.255"),
	},
	{
		start: net.ParseIP("172.16.0.0"),
		end:   net.ParseIP("172.31.255.255"),
	},
	{
		start: net.ParseIP("192.0.0.0"),
		end:   net.ParseIP("192.0.0.255"),
	},
	{
		start: net.ParseIP("192.168.0.0"),
		end:   net.ParseIP("192.168.255.255"),
	},
	{
		start: net.ParseIP("198.18.0.0"),
		end:   net.ParseIP("198.19.255.255"),
	},
}

var tpl *template.Template
var vT visiTracker
var mux sync.Mutex
var mg mailgun.Mailgun
var mEmail, port string
var resumeRequesters map[string]int
var spyImg []byte
var gconn *websocket.Conn

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
	resumeRequesters = make(map[string]int)
	fi, err := ioutil.ReadFile("../numer.json")
	if err == nil {
		json.Unmarshal(fi, &vT)
	} else {
		print("Error reading traffic data")
		os.Exit(1)
	}
	tpl = template.Must(template.New("").Funcs(template.FuncMap{"snapCode": getSnap, "swapViews": (*visiTracker).swapViews, "getIter": getIter}).ParseGlob("templates/*.gohtml"))

	var information info
	fi, err = ioutil.ReadFile("../keys.json")
	if err != nil {
		log.Fatal("Error reading keys data")
	}
	json.Unmarshal(fi, &information)
	mg = mailgun.NewMailgun(information.MailServer, information.Private, information.Public)
	mEmail = information.MyEmail
	if information.Production {
		port = information.ProPort
	} else {
		port = information.DevPort
	}
}

func main() {
	m := melody.New()
	http.HandleFunc("/", index)
	http.HandleFunc("/chat", chat)
	http.HandleFunc("/herdspin", herdSpin)
	http.HandleFunc("/public/", serveFile)
	http.HandleFunc("/sms", sms)
	http.HandleFunc("/spy", spy)
	http.HandleFunc("/wsspy", spyer)
	http.HandleFunc("/wsconnspy", spying)
	http.HandleFunc("/wschat", func(w http.ResponseWriter, r *http.Request) {
		m.HandleRequest(w, r)
	})
	m.HandleMessage(func(s *melody.Session, msg []byte) {
		m.Broadcast(msg)
	})
	err := http.ListenAndServe(port, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
