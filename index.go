package main

import(
	"net/http"
	"math/rand"
	"encoding/json"
	"html/template"
	"io/ioutil"
	"os"
	"time"
	"sync"
	"strings"
	"net"
	"bytes"
	"log"
	"fmt"

	mailgun "gopkg.in/mailgun/mailgun-go.v1"
)

//This, isPrivateSubnet, getIPAdress, and ipRange are from: https://husobee.github.io/golang/ip-address/2015/12/17/remote-ip-go.html
//inRange - check to see if a given ip address is within a range given
func inRange(r ipRange, ipAddress net.IP) bool {
	// strcmp type byte comparison
	if bytes.Compare(ipAddress, r.start) >= 0 && bytes.Compare(ipAddress, r.end) < 0 {
		return true
	}
	return false
}

//Function for determining which snapcode will show on the template
func getSnap() string{
	if rand.Intn(2) == 1{
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
			if inRange(r, ipAddress){
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
		for i := len(addresses) -1 ; i >= 0; i-- {
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
	return ""
}

func writeStructToJson(strct interface{}){
	res, err := json.Marshal(strct)
	if err != nil {
		println(err)
		return
	}
	err = ioutil.WriteFile("../numer.json", res, 0644)
}

func (vT *visiTracker) InSlice(a string) bool {
	for _, b := range vT.IpList {
		if b == a {
			return true
		}
	}
	return false
}

func serveFile(w http.ResponseWriter, r *http.Request){
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
	http.ServeFile(w, r, "./static" + r.URL.Path)
}

func index(w http.ResponseWriter, r *http.Request){
	if r.URL.Query()["check"] == nil{
		mux.Lock()
		vT.V++
		if getIPAdress(r) != "" && !vT.InSlice(getIPAdress(r)) {
			vT.Uv++
			vT.IpList = append(vT.IpList, getIPAdress(r))
		}
		mux.Unlock()
		go writeStructToJson(vT)
	}

	err := tpl.ExecuteTemplate(w, "index.gohtml", vT)
	if err != nil{
		print(err)
	}
}

//ipRange - a structure that holds the start and end of a range of ip addresses
type ipRange struct {
	start net.IP
	end net.IP
}

type visiTracker struct {
	V      int `json:"numb"`
	Uv     int `json:"uniq"`
	IpList []string `json:"ips"`
}

//Struct to hold the private and public keys for the MailGun API
type info struct {
	Private string `json:"private"`
	Public  string `json:"public"`
	MailServer string `json:"mailServer"`
	MyEmail string `json:"myEmail"`
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
var mEmail string
var resumeRequesters map[string]int

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
	tpl = template.Must(template.New("").Funcs(template.FuncMap{"snapcode":getSnap}).ParseGlob("templates/*.gohtml"))

	var information info
	fi, err = ioutil.ReadFile("../keys.json")
	if err != nil {
		log.Fatal("Error reading keys data")
	}
	json.Unmarshal(fi, &information)
	mg = mailgun.NewMailgun(information.MailServer, information.Private, information.Public)
	mEmail = information.MyEmail
}

func main(){
	http.HandleFunc("/", index)
	http.HandleFunc("/public/", serveFile)
	http.ListenAndServe(":3000", nil)
}