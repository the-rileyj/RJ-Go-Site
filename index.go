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
)

//ipRange - a structure that holds the start and end of a range of ip addresses
type ipRange struct {
	start net.IP
	end net.IP
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

type visiTracker struct {
	V      int `json:"numb"`
	Uv     int `json:"uniq"`
	IpList []string `json:"ips"`
}

// inRange - check to see if a given ip address is within a range given
func inRange(r ipRange, ipAddress net.IP) bool {
	// strcmp type byte comparison
	if bytes.Compare(ipAddress, r.start) >= 0 && bytes.Compare(ipAddress, r.end) < 0 {
		return true
	}
	return false
}

var tpl *template.Template
var vT visiTracker
var mux sync.Mutex

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
	fi, err := ioutil.ReadFile("../numer.json")
	if err == nil {
		json.Unmarshal(fi, &vT)
	} else {
		print("ERRRRRRRRRRR")
		os.Exit(1)
	}
	tpl = template.Must(template.New("").Funcs(template.FuncMap{"snapcode":getSnap}).ParseGlob("templates/*.gohtml"))
	//tpl.ParseGlob("templates/*.gohtml")
}

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
/*
func hack(w http.ResponseWriter, r *http.Request){
	var buffer bytes.Buffer
	count := 0
	for k, v := range r.URL.Query(){
		buffer.WriteString(fmt.Sprintf("ayyy\n%v - %v\n", k, v))
		if count++; count > 10 {
			break
		}
	}
	ioutil.WriteFile("outer.txt", buffer.Bytes(), 0644)
	fmt.Fprintf(w, "%v, %v, %v", r.URL.Query()["l"][0], r.URL.Query()["w"][0], r.URL.Query()["c"][0])
}*/


func main(){
	http.HandleFunc("/", index)
	//http.HandleFunc("/hack", hack)
	http.Handle("/public/", http.FileServer(http.Dir("static/")))
	http.ListenAndServe(":3000", nil)
}