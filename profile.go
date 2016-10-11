package hello

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"time"

	bigquery "google.golang.org/api/bigquery/v2"
	"google.golang.org/appengine"

	"golang.org/x/oauth2/google"
)

//JWT .
type JWT struct {
	Header  Header
	Payload Payload
}

//Header .
type Header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

//Payload .
type Payload struct {
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`
	IssuedAt int    `json:"iat,string"`
	Expire   int    `json:"exp,string"`
}

//SignBlobIn .
type SignBlobIn struct {
	BytesToSign []byte `json:"bytesToSign"`
}

//SignBlobResponse .
type SignBlobResponse struct {
	KeyID     string `json:"keyID"`
	Signature []byte `json:"signature"`
}

func init() {
	http.HandleFunc("/cron", cron)
	http.HandleFunc("/", handler)
}

//BlobToSign .
func (jwt *JWT) BlobToSign() string {
	headerBytes, _ := json.Marshal(jwt.Header)
	payloadBytes, _ := json.Marshal(jwt.Payload)
	return Encode(headerBytes) + "." + Encode(payloadBytes)
}

func verifySignature(blob string, signature []byte, pemCert string) error {

	publicKey, err := extractPublicKey(pemCert)
	if err != nil {
		return err
	}

	hash := sha256.New()
	hash.Write([]byte(blob))
	digest := hash.Sum(nil)

	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest, signature)
}

func extractPublicKey(x509PEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(x509PEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}
	cert, err := x509.ParseCertificate(block.Bytes)

	if err != nil {
		return nil, errors.New("failed to parse certificate: " + err.Error())
	}
	return cert.PublicKey.(*rsa.PublicKey), nil
}

//Encode .
func Encode(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

func sign(jwt JWT, client *http.Client) (*SignBlobResponse, error) {
	blobToSign := base64.URLEncoding.EncodeToString([]byte(jwt.BlobToSign()))
	url := "https://iam.googleapis.com/v1/projects/lightweight-client-auth/serviceAccounts/lightweight-client-auth@appspot.gserviceaccount.com:signBlob"
	signBlobIn := SignBlobIn{
		BytesToSign: []byte(blobToSign),
	}
	postBody := new(bytes.Buffer)
	json.NewEncoder(postBody).Encode(signBlobIn)
	req, err := http.NewRequest("POST", url, postBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	decoder := json.NewDecoder(resp.Body)
	var signResponse SignBlobResponse
	decoder.Decode(&signResponse)
	return &signResponse, nil
}

func verify(jwt JWT, s *SignBlobResponse, client *http.Client) error {
	sig := s.Signature
	keyID := s.KeyID
	url2 := "https://www.googleapis.com/service_accounts/v1/metadata/x509/lightweight-client-auth@appspot.gserviceaccount.com"
	reqz, err := http.NewRequest("GET", url2, nil)
	reqz.Header.Set("Content-Type", "application/json")
	respz, err := client.Do(reqz)
	if err != nil {
		return err
	}
	defer respz.Body.Close()
	decoder2 := json.NewDecoder(respz.Body)
	certs := make(map[string]string)
	decoder2.Decode(&certs)
	blobToSign := base64.URLEncoding.EncodeToString([]byte(jwt.BlobToSign()))
	return verifySignature(blobToSign, sig, certs[keyID])

}

func log(op string, result bool, duration time.Duration, client *http.Client) {
	c, err := bigquery.New(client)
	if err != nil {
		return
	}
	ts := time.Now().Unix()
	data := map[string]bigquery.JsonValue{
		"operation": op,
		"timestamp": ts,
		"result":    result,
		"duration":  duration.Nanoseconds(),
	}
	request := new(bigquery.TableDataInsertAllRequest)
	request.Rows = []*bigquery.TableDataInsertAllRequestRows{{Json: data}}
	c.Tabledata.InsertAll("lightweight-client-auth", "jwtProfiling", "data", request).Do()
}

func readLog(client *http.Client) []*bigquery.TableRow {
	c, err := bigquery.New(client)
	if err != nil {
		return nil
	}
	list, _ := c.Tabledata.List("lightweight-client-auth", "jwtProfiling", "data").Do()
	return list.Rows
}

func cron(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	client, err := google.DefaultClient(c, "https://www.googleapis.com/auth/cloud-platform")
	var jwt JWT
	jwt.Header = Header{
		Algorithm: "RS256",
		Type:      "JWT",
	}
	jwt.Payload = Payload{
		Issuer:   "i",
		Audience: "a",
		IssuedAt: 1,
		Expire:   2,
	}
	start := time.Now()
	signResponse, err := sign(jwt, client)
	elapsed := time.Since(start)
	if err != nil {
		log("sign", false, 0, client)
		return
	}
	log("sign", true, elapsed, client)
	fmt.Fprintf(w, "Signing took %s<br><br>", elapsed)
	if err != nil {
		fmt.Fprint(w, err)
	}
	start2 := time.Now()
	err = verify(jwt, signResponse, client)
	elapsed2 := time.Since(start2)
	fmt.Fprintf(w, "Verification took %s", elapsed2)
	if err != nil {
		log("verification", false, 0, client)
		return
	}
	log("verification", true, elapsed2, client)
}

type int64arr []int64

func (a int64arr) Len() int {
	return len(a)
}
func (a int64arr) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}
func (a int64arr) Less(i, j int) bool {
	return a[i] < a[j]
}

func median(numbers []int64) int64 {
	middle := len(numbers) / 2
	result := numbers[middle]
	if len(numbers)%2 == 0 {
		result = (result + numbers[middle-1]) / 2
	}
	return result
}

func mean(numbers []int64) int64 {
	var total int64
	for _, i := range numbers {
		total += i
	}
	return total / int64(len(numbers))
}

func handler(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	client, _ := google.DefaultClient(c, "https://www.googleapis.com/auth/cloud-platform")
	logs := readLog(client)
	failedS := 0
	totalS := 0
	failedV := 0
	totalV := 0
	sTimes := make([]int64, 0)
	vTimes := make([]int64, 0)
	for _, entry := range logs {
		op, _ := entry.F[0].V.(string)
		//ts, _ := entry.F[1].V.(string)
		//timestamp, _ := strconv.ParseInt(ts, 10, 64)
		ds, _ := entry.F[2].V.(string)
		duration, _ := strconv.ParseInt(ds, 10, 64)
		duration = duration / 1000000
		rs, _ := entry.F[3].V.(string)
		result := false
		if rs == "true" {
			result = true
		}
		if op == "sign" {
			totalS++
			if result == false {
				failedS++
			} else {
				sTimes = append(sTimes, duration)
			}
		}
		if op == "verification" {
			totalV++
			if result == false {
				failedV++
			} else {
				vTimes = append(vTimes, duration)
			}
		}
		//tm := time.Unix(timestamp, 0)
	}
	sort.Sort(int64arr(sTimes))
	fmt.Fprint(w, "This app runs sign and verify operations in a cron job, once every two minutes.<br> Their execution times and failure rates are measured and written to a BigQuery table.<br> Here are some stats from the table.<br><br>")
	fmt.Fprint(w, "Signing:<br>")
	fmt.Fprintf(w, "Total: %d, Success: %d, Failed: %d<br>", totalS, totalS-failedS, failedS)
	fmt.Fprintf(w, "Median time to sign: %d milliseconds.<br><br>", median(sTimes))
	sort.Sort(int64arr(vTimes))
	fmt.Fprint(w, "Verification:<br>")
	fmt.Fprintf(w, "Total: %d, Success: %d, Failed: %d<br>", totalV, totalV-failedV, failedV)
	fmt.Fprintf(w, "Median time to verify: %d milliseconds.<br><br>", median(vTimes))
}
