/*
* NIST-developed software is provided by NIST as a public service. You
* may use, copy and distribute copies of the software in any medium,
* provided that you keep intact this entire notice. You may improve,
* modify and create derivative works of the software or any portion of
* the software, and you may copy and distribute such modifications or
* works. Modified works should carry a notice stating that you changed
* the software and should note the date and nature of any such
* change. Please explicitly acknowledge the National
* Institute of Standards and Technology as the source of the software.

* NIST-developed software is expressly provided “AS IS.” NIST MAKES NO
* WARRANTY OF ANY KIND, EXPRESS, IMPLIED, IN FACT OR ARISING BY
* OPERATION OF LAW, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
* WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE,
* NON-INFRINGEMENT AND DATA ACCURACY. NIST NEITHER REPRESENTS NOR
* WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE UNINTERRUPTED OR
* ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST DOES NOT
* WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE
* SOFTWARE OR THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE
* CORRECTNESS, ACCURACY, RELIABILITY, OR USEFULNESS OF THE SOFTWARE.

* You are solely responsible for determining the appropriateness of
* using and distributing the software and you assume all risks
* associated with its use, including but not limited to the risks and
* costs of program errors, compliance with applicable laws, damage to
* or loss of data, programs or equipment, and the unavailability or
* interruption of operation. This software is not intended to be used
* in any situation where a failure could cause risk of injury or
* damage to property. The software developed by NIST employees is not
* subject to copyright protection within the United States.
*/

package main

import (
	"fmt"
	"errors"
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"flag"
	"strings"
	"time"
	"github.com/miekg/dns"
	"net/http"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

const (
	// DefaultTimeout is default timeout many operation in this program will
	// use.
	DefaultTimeout time.Duration = 5 * time.Second
)

type zoneEmailPosture struct {
	Id string `json:"id" bson:"_id,omitempty"`
	Zname string `json:"zname" bson:"zname"`
	Agency string `json:"agency" bson:"agency"`
	Time int64 `json:"time" bson:"time"`
	Spf string `json:"spf" bson:"spf"`
	DkimSelect string `json:"dkimselect" bson:"dkimselect"`
	Dkim string `json:"dkim" bson:"dkim"`
	Dmarc string `json:"dmarc" bson:"dmarc"`
	Dane bool `json:"dane" bson:"dane"`
	Mx []string `json:"mx" bson:"mx"`
	SmtpSts string `json:"smtpsts" bson:"smtpsts"`
	StsPolicy []string `json:"stspolicy" bson:"stspolicy"`
	TlsReport string `json:"tlsreport" bson:"tlsreport"`
	StartTLS bool `json:"starttls" bson:"starttls"`
	RequireTLS bool `json:"requiretls" bson:"requiretls"`
	BlockTLS bool `json:"blocktls" bson:"blocktls"`
	Cert string `json:"cert" bson:"cert"`
}

type serverStatus struct {
	starttls bool
	blocked	bool
	requiretls bool
	tlsCert string
}

var (
	query *dns.Msg
	myRes *dns.Client
	conf  *dns.ClientConfig
	usrName	string
	dbPass	string
	dbUrl string
	dbName string
	inputList string
	fulltest string
	serverMap = make(map[string]serverStatus)
)

func doQuery(qname string, qtype uint16, validate bool) (*dns.Msg, error) {
	query := new (dns.Msg)
	query.RecursionDesired = true
	query.SetEdns0(4096, validate)
	query.SetQuestion(dns.Fqdn(qname), qtype)
	
	for i := range conf.Servers {
		server := conf.Servers[i]
		r, _, err := myRes.Exchange(query, server+":"+conf.Port)
		if err != nil || r == nil {
			return nil, err
		} else {
			return r, err
		}
	}
	return nil, errors.New("No name server to answer the question")
}

func getPolicy(qname string, idStr string) (string) {
	var err error
	
	resp,err := doQuery(qname, dns.TypeTXT, false)
	if err != nil || resp == nil {
		return "none"
	}
	//NEED TO CHANGE: have the Contains deal with upper/lower case
	for _, aRR := range resp.Answer {
		switch aRR := aRR.(type) {
			case *dns.TXT:
				rdata := strings.Join(aRR.Txt, " ")
				if (strings.Contains(rdata, idStr)) {
					return rdata
				}
		}
	}
	return "none"
}

func getJson(domain string) ([]string) {
	var lines []string
			
	url := "https://mta-sts." + domain + "/.well-known/mta-sts.txt"
	resp, err := http.Get(url)
	if (err == nil) {
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return nil
		}
		return lines
	}
		
	defer resp.Body.Close()
	
	return nil
}

func getMXList(qname string) ([]string) {
	var resp *dns.Msg
	var err error
	var exchanges []string
	
	resp,err = doQuery(qname, dns.TypeMX, false)
	if err != nil || resp == nil {
		return []string{"null"}
	}
	if (len(resp.Answer) == 0) {
		exchanges = append(exchanges, "none")
	} else {
		for _, aRR := range resp.Answer {
			switch aRR := aRR.(type) {
				case *dns.MX:
					exchanges = append(exchanges, aRR.Mx)
			}
		}
	} 
	return exchanges
}
	
func getSecondLevel(mailSrv string) (string) {
	var second string
	
	levels := strings.Split(mailSrv, ".")
	if (len(levels) < 3) {
		second = mailSrv
	} else { 
		second = levels[len(levels)-3] + "." + levels[len(levels)-2]
	}
	return second 
}	

func getSMTPOptions(testExch string ) (bool, bool, bool, string){
	var starttls bool
	var requiretls bool
	var blocktls bool
	var srvCert string
	starttls = false
	requiretls = false
	blocktls = false
	
	srvRec, found := serverMap[getSecondLevel(testExch)]
	if (!found) {
		cmd := exec.Command("./getUTF8", testExch)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			fmt.Println("cmd.StdoutPipe() error: " + err.Error())
		}
		if err := cmd.Start(); err != nil {
			fmt.Println(err)
		}
		
		// setup a buffer to capture standard output
		var buf bytes.Buffer

		// create a channel to capture any errors from wait
		done := make(chan error)
		go func() {
			if _, err := buf.ReadFrom(stdout); err != nil {
				panic("buf.Read(stdout) error: " + err.Error())
			}
			done <- cmd.Wait()
		}()
		select {
		case <-time.After(10 * time.Second):
			if err := cmd.Process.Kill(); err != nil {
				fmt.Println("failed to kill process: ", err)
			}
			fmt.Println(testExch + ": process killed as timeout reached")
		case err := <-done:
			if err != nil {
				close(done)
				fmt.Println("process done, with error: " + err.Error())
			}
			value := buf.String()
			retLine := strings.Split(value, ",")
			if (retLine[1] == "1") {
				starttls = true
			}
			if (retLine[2] == "1") {
				requiretls = true
			}
			if (retLine[3] == "1") {
				blocktls = true
			}
			srvCert = retLine[4]
			
 			var newEntry serverStatus
			newEntry.starttls = starttls
			newEntry.requiretls = requiretls
			newEntry.blocked = blocktls
			newEntry.tlsCert = srvCert
			
			serverMap[getSecondLevel(testExch)] = newEntry
		} 
	} else {
		starttls = srvRec.starttls
		requiretls = srvRec.requiretls
		blocktls = srvRec.blocked
		srvCert = srvRec.tlsCert
	}
	
	return starttls, requiretls, blocktls, srvCert
}

func parseConfigFile(filename string) {
	if file, err := os.Open(filename); err == nil {
		defer file.Close()
		
		fulltest = "no"
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.Split(scanner.Text(), "=")
			switch (line[0]) {
				case ("user"):
					usrName = line[1]
				case ("db"):
					dbName = line[1]
				case ("url"):
					dbUrl = line[1]
				case ("pass"):
					dbPass = line[1]
				case ("input"):
					inputList = line[1]
				case ("full"):
					fulltest = line[1]
			}
		}
	}
}


func main() {
	var err error
	var line []string
	var session *mgo.Session	
	
	//get the arguements
	confFile := flag.String("config", "monitor.conf", "The configuration file")
	flag.Parse()
		
	parseConfigFile(*confFile)
	
	conf, err = dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || conf == nil {
		fmt.Printf("Cannot initialize the local resolver: %s\n", err)
		os.Exit(1)
	}
	query = &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
			CheckingDisabled: true,
		},
		Question: make([]dns.Question, 1),
	}
	myRes = &dns.Client{
		ReadTimeout: DefaultTimeout,
	}
	
	// open the input file
	if file, err := os.Open(inputList); err == nil {
		// make sure it gets closed
		defer file.Close()
		var zonename string
		
		//connect to db
		monDBDialInfo := &mgo.DialInfo{
			Addrs: []string{dbUrl},
			Timeout: 60 * time.Second,
			Database: "email",
			Username: usrName,
			Password: dbPass,
		}
		session, err = mgo.DialWithInfo(monDBDialInfo)
		if (err != nil) {
			panic (err.Error())
		}
		session.SetSafe(&mgo.Safe{})
		cur := session.DB("email").C(dbName)
		index := mgo.Index{
				Key:        []string{"zname"},
				Unique:     true,
				DropDups:   true,
				Background: true,
				Sparse:     true,
		}
		err = cur.EnsureIndex(index)
		if err != nil {
			panic(err)
		}
		
		// create a new scanner and read the file line by line
		scanner := bufio.NewScanner(file)
		
		for scanner.Scan() {
			time.Sleep(20 * time.Second)
			var zoneData zoneEmailPosture
			var isNew = false
			line = strings.Split(scanner.Text(), ",")
			zonename = dns.Fqdn(line[0])
			//check to see if it exists already, if so, use that, else it is new
			err = cur.Find(bson.M{"zname": zonename}).One(&zoneData)
			if err != nil {
				isNew = true
				zoneData.Zname = zonename
				zoneData.Agency = line[2]
			}
			zoneData.Time = time.Now().Unix()
			zoneData.Spf = getPolicy(zonename, "v=spf1")
			//now DMARC
			zoneData.Dmarc = getPolicy(("_dmarc." + zonename), "v=DMARC1;")
			//now SMTP-STS
			zoneData.SmtpSts = getPolicy(("_mta-sts." + zonename), "v=STSv1;")
			if (strings.Compare(zoneData.SmtpSts, "none") != 0) {
				zoneData.StsPolicy = getJson(line[0])
			}
			//look for TLS Reporting policy
			zoneData.TlsReport = getPolicy(("_smtp-tlsrpt." + zonename), "v=TLSRPTv1;")
			//get MX list and STARTTLS status
			zoneData.Mx = getMXList(zonename)
			//Look for DANE RRs
			if (zoneData.Mx[0] != "none") {
				for i,mx range zoneData.Mx {
					resp,err = doQuery(mx, dns.TypeTLSA, false)
					if err == nil || resp != nil {
						if (len(resp.Answer) > 0) {
							for _, aRR := range resp.Answer {
								switch aRR := aRR.(type) {
									case *dns.TLSA:
										zoneData.Dane = true
								}
							} 
						} 
					}
				}
			}
			if (fulltest == "yes") {
				if (zoneData.Mx[0] != "none") {
					zoneData.StartTLS, zoneData.RequireTLS, zoneData.BlockTLS, zoneData.Cert = getSMTPOptions(zoneData.Mx[0])
				}
			} 
			//now put it in the database
			nameKey := bson.M{"zname": zoneData.Zname }
			if (isNew) {
				_, err = cur.Upsert(nameKey, zoneData)
				if (err != nil) {
					panic(err.Error())
				}
			} else {
				zoneData.Id = ""	
				err = cur.Update(nameKey, zoneData)
				if (err != nil) {
					panic(err.Error())
				}
			}
						
		}
		// check for errors
		if err = scanner.Err(); err != nil {
			fmt.Println("Error in reading")
		}
		
		session.Close()
	} else {
		fmt.Println("Error in opening file")
	}

}
