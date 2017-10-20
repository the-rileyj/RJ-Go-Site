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
	"github.com/gorilla/websocket"
	//"encoding/base64"
	"io"
	//"image/png"
	"image"

	mailgun "gopkg.in/mailgun/mailgun-go.v1"
	"image/png"
	"encoding/base64"
)

//Notes:
//Fix IP log
//Influences From:
//https://github.com/jex-lin/golang-push-image-via-websocket-example/blob/master/main.go

func (c *Client) write() {
	defer func() {
		c.socket.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				c.socket.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			c.socket.WriteMessage(websocket.TextMessage, message)
		}
	}
}

func (c *Client) read() {
	defer func() {
		manager.unregister <- c
		c.socket.Close()
	}()

	for {
		_, message, err := c.socket.ReadMessage()
		if err != nil {
			manager.unregister <- c
			c.socket.Close()
			break
		}
		jsonMessage, _ := json.Marshal(&Message{Sender: c.id, Content: string(message)})
		manager.broadcast <- jsonMessage
	}
}

func (manager *ClientManager) send(message []byte, ignore *Client) {
	for conn := range manager.clients {
		if conn != ignore {
			conn.send <- message
		}
	}
}

func (manager *ClientManager) start() {
	for {
		select {
		case conn := <-manager.register:
			manager.clients[conn] = true
			jsonMessage, _ := json.Marshal(&Message{Content: "/A new socket has connected."})
			manager.send(jsonMessage, conn)
		case conn := <-manager.unregister:
			if _, ok := manager.clients[conn]; ok {
				close(conn.send)
				delete(manager.clients, conn)
				jsonMessage, _ := json.Marshal(&Message{Content: "/A socket has disconnected."})
				manager.send(jsonMessage, conn)
			}
		case message := <-manager.broadcast:
			for conn := range manager.clients {
				select {
				case conn.send <- message:
				default:
					close(conn.send)
					delete(manager.clients, conn)
				}
			}
		}
	}
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

func writeStructToJson(strct interface{}, path string){
	res, err := json.Marshal(strct)
	if err != nil {
		println(err)
		return
	}
	err = ioutil.WriteFile(path, res, 0644)
}

func (vT *visiTracker) InSlice(a string) bool {
	for _, b := range vT.IpList {
		if b == a {
			return true
		}
	}
	return false
}

func getIter()[]int {
	return make([]int, 1000);
}

func (vT *visiTracker) swapViews() visiTracker {
	return visiTracker{vT.GspinV, vT.Uv, vT.V,vT.IpList}
}

//From: https://stackoverflow.com/questions/40684307/how-can-i-receive-an-uploaded-file-using-a-golang-net-http-server
func getPicture(w http.ResponseWriter, r *http.Request) {
	var Buf bytes.Buffer
	// in your case file would be fileupload
	file, header, err := r.FormFile("file")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	name := strings.Split(header.Filename, ".")
	fmt.Printf("File name %s\n", name[0])
	// Copy the file data to my buffer
	io.Copy(&Buf, file)
	// do something with the contents...
	// I normally have a struct defined and unmarshal into a struct, but this will
	// work as an example
	contents := Buf.String()
	fmt.Println(contents)
	// I reset the buffer in case I want to use it again
	// reduces memory allocations in more intense projects
	Buf.Reset()
	// do something else
	// etc write header
	return
}

func herdSpin(w http.ResponseWriter, r *http.Request) {
	err := tpl.ExecuteTemplate(w, "herdspin.gohtml", vT)
	if err != nil{
		print(err)
	}
}

func spy(w http.ResponseWriter, r *http.Request) {

}

func spyer(w http.ResponseWriter, r *http.Request) {
	conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
	if _, ok := err.(websocket.HandshakeError); ok {
		fmt.Println( "Not a websocket handshake")
		return
	} else if err != nil {
		log.Printf("%s\nError in establishing WS with spyer\n", err)
		return
	}
	for {
		_, p, err := conn.ReadMessage()
		if err != nil {
			fmt.Printf("%s\nError with recieving websocket connection\n", err)
			return
		}
		spyImg, err = png.Decode(base64.NewDecoder(base64.StdEncoding, strings.NewReader(string(p))))
		if err != nil {
			fmt.Printf("%s\nError decoding image\n", err)
		}
		out, err := os.Create("out.png")
		if err != nil {
			fmt.Println(0, err)
			return
		}

		err = png.Encode(out, spyImg)

		if err != nil {
			fmt.Println(1, err)
			return
		}
	}
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
	http.ServeFile(w, r, "./static" + r.URL.Path)
}

func index(w http.ResponseWriter, r *http.Request){
	if r.URL.Query()["check"] == nil {
		mux.Lock()
		vT.V++
		if getIPAdress(r) != "" && !vT.InSlice(getIPAdress(r)) {
			vT.Uv++
			vT.IpList = append(vT.IpList, getIPAdress(r))
		}
		mux.Unlock()
		go writeStructToJson(vT, "../numer.json")
	}

	err := tpl.ExecuteTemplate(w, "index.gohtml", vT)
	if err != nil{
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
	end net.IP
}

type visiTracker struct {
	V      int `json:"numb"`
	Uv     int `json:"uniq"`
	GspinV int `json:"gnumb"`
	IpList []string `json:"ips"`
}

//Struct to hold the private and public keys for the MailGun API
type info struct {
	Private string `json:"private"`
	Public  string `json:"public"`
	MailServer string `json:"mailServer"`
	MyEmail string `json:"myEmail"`
	Spyl string `json:"spyLogin"`
	Spyp string `json:"spyPass"`
	GPass string `json:"gPass"`
	Sid string `json:"sid"`
	Token string `json:"token"`
	Number string `json:"number"`
	LyricKey string `json:"lyric_key"`
	Production bool `json:"production"`
	ProPort string `json:"pro-port"`
	DevPort string `json:"dev-port"`
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

type ClientManager struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
}

type Client struct {
	id     string
	socket *websocket.Conn
	send   chan []byte
}

type Message struct {
	Sender    string `json:"sender,omitempty"`
	Recipient string `json:"recipient,omitempty"`
	Content   string `json:"content,omitempty"`
}


var manager = ClientManager{
	broadcast:  make(chan []byte),
	register:   make(chan *Client),
	unregister: make(chan *Client),
	clients:    make(map[*Client]bool),
}
var tpl *template.Template
var vT visiTracker
var mux sync.Mutex
var mg mailgun.Mailgun
var mEmail, port string
var resumeRequesters map[string]int
var spyImg image.Image

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
	tpl = template.Must(template.New("").Funcs(template.FuncMap{"snapCode":getSnap, "swapViews":(*visiTracker).swapViews, "getIter":getIter}).ParseGlob("templates/*.gohtml"))

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

func main(){
	go manager.start()
	http.HandleFunc("/", index)
	http.HandleFunc("/spyer", spyer)
	http.HandleFunc("/sms", sms)
	http.HandleFunc("/spy", spy)
	http.HandleFunc("/test", spyer)
	http.HandleFunc("/herdspin", herdSpin)
	http.HandleFunc("/public/", serveFile)
	err := http.ListenAndServe(port, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}