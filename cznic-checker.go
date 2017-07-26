package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// BaseURL Url to send queries to.
const BaseURL = "https://www.nic.cz/whois/domain/"

// Politeness factor. Don't be evil.
const Politeness = 1 * time.Second

// HaystackCaptcha means the captcha is displayed.
const HaystackCaptcha = "Kontrolní kód"

// HaystackFree means the domain is free to register.
const HaystackFree = "nebyla nalezena"

// HaystackExpiration is used to find the expiration date offset.
const HaystackExpiration = "Datum expirace"

// ExpirationOffset = (the start of the date) - HaystackExpiration
const ExpirationOffset = 72

// ExpirationLength is length of the expiration date format.
const ExpirationLength = 10

// CheckResult holds the result of a domain check.
type CheckResult struct {
	URL        string
	IsFree     bool
	Expiration time.Time
}

func getPageContent(url string) (string, error) {
	response, e := http.Get(url)

	if e != nil {
		return "", e
	}

	if response.StatusCode != 200 {
		return "", errors.New("Returned code " + strconv.Itoa(response.StatusCode))
	}

	defer response.Body.Close()

	buf := new(bytes.Buffer)
	buf.ReadFrom(response.Body)

	return buf.String(), nil
}

func waitForUser() {
	reader := bufio.NewReader(os.Stdin)
	reader.ReadString('\n')
}

func strToDate(date string) (time.Time, error) {
	str := fmt.Sprintf("%s-%s-%sT00:00:00.000Z", date[6:], date[3:5], date[0:2])
	return time.Parse(time.RFC3339, str)
}

func reportDay(expiration int) string {
	if expiration < 0 {
		expiration = -expiration
	}

	switch {
	case expiration == 0:
		return "today"
	case expiration == 1:
		return "1 day"
	default:
		return strconv.Itoa(expiration) + " days"
	}
}

func report(result *CheckResult) {
	res := ""
	if result.IsFree {
		res = "Free"
	} else {
		exp := int((result.Expiration.Sub(time.Now())).Hours() / 24)
		day := reportDay(exp)

		switch {
		case exp == 0:
			res = fmt.Sprintf("Expires %s", day)
			break
		case exp < 0:
			res = fmt.Sprintf("Expired %s ago", day)
			break
		default:
			res = fmt.Sprintf("Expires in %s", day)
		}
	}

	log.Printf("%s\t%s\n", result.URL, res)
}

func processURLResult(url, content string) (*CheckResult, error) {
	ret := new(CheckResult)
	ret.URL = url
	ret.IsFree = strings.Contains(content, HaystackFree)

	if ret.IsFree {
		return ret, nil
	}

	index := strings.Index(content, HaystackExpiration)
	sub := content[index+ExpirationOffset : index+ExpirationOffset+ExpirationLength]

	var err error
	ret.Expiration, err = strToDate(sub)

	if err != nil {
		return nil, err
	}

	return ret, nil
}

func normalizeCzURL(urlAddr string) (string, error) {
	if !strings.HasPrefix(urlAddr, "http://") {
		urlAddr = "http://" + urlAddr
	}

	if !strings.HasSuffix(urlAddr, ".cz") {
		urlAddr = urlAddr + ".cz"
	}

	parsed, e := url.Parse(urlAddr)

	if e != nil {
		return "", e
	}

	if strings.Count(parsed.Host, ".") > 1 {
		return "", errors.New("You can check only second-level .cz domains")
	}

	return parsed.Host, nil
}

// CheckURL checks if a domain (url) is free to register.
func CheckURL(url string) (*CheckResult, error) {
	content := ""
	normalizedURL, err := normalizeCzURL(url)

	if err != nil {
		return nil, err
	}

	for {
		query := BaseURL + normalizedURL
		pageContent, err := getPageContent(query)

		if err != nil {
			return nil, err
		}

		if strings.Contains(pageContent, HaystackCaptcha) {
			fmt.Printf("Go to %s and check the captcha.\nPress enter to continue.", query)
			waitForUser()
		} else {
			content = pageContent
			break
		}
	}

	return processURLResult(normalizedURL, content)
}

func processURL(url string) {
	result, err := CheckURL(url)

	if err != nil {
		log.Fatalf("%s\t%s", url, err)
	} else {
		report(result)
		time.Sleep(Politeness)
	}
}

func getUserURL() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\nEnter domain: ")
	domain, _ := reader.ReadString('\n')
	return strings.Replace(domain, "\n", "", -1)
}

func startArgLoop() {
	urls := flag.Args()

	for _, url := range urls {
		processURL(url)
	}
}

func startInteractiveLoop() {
	for {
		processURL(getUserURL())
	}
}

func printUsage() {
	fmt.Printf("Usage: %s domain1[.cz][ domain2[ domain3]...]\n", os.Args[0])
	fmt.Println("Available arguments:")
	flag.PrintDefaults()
}

func main() {
	interactive := flag.Bool("i", false, "Interactive mode")
	flag.Parse()

	if *interactive {
		fmt.Println("Press CTRL-C to quit.")
		startInteractiveLoop()
	} else {
		if len(flag.Args()) > 0 {
			startArgLoop()
		} else {
			printUsage()
		}
	}
}
