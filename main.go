/*                 EMAIL VERIFIYER TOOL

SAMPLE INPUT:
    google.com       -> domain name

SAMPLE OUTPUT:
Domain, hasMX , hasSPF , SPFrecord, hasDMARC , DMARCrecord
google.com
google.com, true, true, v=spf1 include:_spf.google.com ~all, true, v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com

*/

package main

import (
	"bufio"   // provides I/O operations.
	"fmt"     // used to print , scan and format data.
	"log"     //This package is used to record and report errors, warnings, or other information during the execution of a Go program.
	"net"     // Net package provides set of functions and types for working with network connections such as tcp/IP , udp , dns ,  unix domain sockets.
	"os"      //the os package provides a set of functions and types for working with the operating system, including file operations, environment variables, command-line arguments, and process management.
	"strings" // the strings package provides a set of functions for manipulating strings.
)

func main() {

	scanner := bufio.NewScanner(os.Stdin)

	fmt.Printf("Domain, hasMX , hasSPF , SPFrecord, hasDMARC , DMARCrecord\n")

	for scanner.Scan() {
		checkDomain(scanner.Text())
	}

	if err := scanner.Err(); err != nil {

		log.Printf("ERROR: Could not read from the Input :%v\n", err)
	}

}

func checkDomain(Domain string) {

	var hasMX, hasSPF, hasDMARC bool
	var SPFrecord, DMARCrecord string

	mxRecord, err := net.LookupMX(Domain) // For MX[mail sever] records . It checks the mail server records for particular domain and routes it to receiver.

	if err != nil {
		log.Printf("Error:%v\n", err)
	}

	if len(mxRecord) > 0 {
		hasMX = true
	}

	txtRecords, err := net.LookupTXT(Domain) // For SPF[sender policy framework] records. It checks that the mail was sent from valid server .

	if err != nil {
		log.Printf("Error:%v\n", err)
	}

	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=spf1") {
			hasSPF = true
			SPFrecord = record
			break
		}
	}

	dmarcRecords, err := net.LookupTXT("_DMARC." + Domain) // For DMARC[Domain based message authentication , reporting and conformace record ] records . It specifies that how mails that fail spf should be handled and gives the feedback to the owners of domain about attempt to sent fraudelent mails from their domain.

	if err != nil {
		log.Printf("Error:%v\n", err)
	}

	for _, record := range dmarcRecords {
		if strings.HasPrefix(record, "v=DMARC1") {
			hasDMARC = true
			DMARCrecord = record
			break
		}
	}

	fmt.Printf("%v, %v, %v, %v, %v, %v", Domain, hasMX, hasSPF, SPFrecord, hasDMARC, DMARCrecord)
}
