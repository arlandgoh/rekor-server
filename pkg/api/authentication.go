package api

import (
	"crypto/tls"
	"fmt"
	"golang.org/x/exp/slices"
)

func getSerialNumber(state *tls.ConnectionState) []string {
	var serialNumberList []string
	for _, cert := range state.PeerCertificates {
		serialNumber := cert.SerialNumber
		// fmt.Printf("Serial Number: %v\n", serialNumber)
		serialNumberList = append(serialNumberList, serialNumber.String())
	}
	return serialNumberList
}

func getCommonName(state *tls.ConnectionState) []string {
	var commonNameList []string
	for _, cert := range state.PeerCertificates {
		subject := cert.Subject
		// fmt.Printf("allowlist: %v", viper.GetStringSlice("common_name_allowlist"))
		commonNameList = append(commonNameList, subject.CommonName)
	}
	return commonNameList
}

func getSanEntry(state *tls.ConnectionState) []string {
	var SanEntryList []string
	for _, cert := range state.PeerCertificates {
		dnsEntry := cert.DNSNames
		// log.Printf("dnsEntry: %v", dnsEntry)
		SanEntryList = append(SanEntryList, dnsEntry...)
	}
	return SanEntryList
}

func isAuthorised(commonNameAllowList []string, sanEntryList []string, commonName string) bool { //serialNumberAllowList []string, //, serialNumber string
	
	var passSAN bool
	resultSlice := []string{}
	checkMap := map[string]struct{}{}

	// CN Validation
	passCN := slices.Contains(commonNameAllowList, commonName) 

	// Matching between allowlist and SAN
	for _, commonName := range commonNameAllowList {
		checkMap[commonName] = struct{}{}
	}
	for _, commonName := range sanEntryList {
		if _, ok := checkMap[commonName]; ok {
			resultSlice = append(resultSlice, commonName)
		}
	}

	fmt.Printf("PASS CN SAN %v", resultSlice)

	if len(resultSlice) > 0 {
		passSAN = true
    } else {
		passSAN = false
    }

	//fmt.Printf("PASS CN %t", passCN)
	//fmt.Printf("PASS SAN %t", passSAN)

	return passCN || passSAN
}
