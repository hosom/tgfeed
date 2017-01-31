/*
Sync up Threatgrid intelligence data with Bro.
*/

package main

import (
    "flag"
    "os"
    "fmt"
    "net/http"
    "time"
    "log"
    "io/ioutil"
    "encoding/json"

    "github.com/hosom/gobrointel"
)

const (
    // URI format to use when a date is specified
    base_date_uri = "https://panacea.threatgrid.com/api/v3/feeds/%s_%s.json?api_key=%s"
    // URI format to use when a date is not specified
    base_uri = "https://panacea.threatgrid.com/api/v3/feeds/%s.json?api_key=%s"
)

// ThreatgridReport is a struct to contain JSON objects returned by Threatgrid
type ThreatgridReport struct {
    // A short description of the feed retrieved
    Description         string
    // Domain attempted to resolve
    Domain              string
    // Link to AMP threat grid entity page with details on domain
    Info                string
    // List of IP addresses, if available
    Ips                 []string
    // Link to sample in threat grid to provide deeper context
    Sample              string
    // MD5 of associated sample
    SampleMD5           string      `json:"sample_md5"`
    // SHA256 of associated sample
    SampleSHA256        string
    // Time analysis was performed
    Timestamp           string
}

func usage() {
    fmt.Printf("Usage: %s [OPTIONS] feed_name api_key\n", os.Args[0])
    fmt.Print(`Possible Feed Values
==============================================================================
autorun-registry            Contains registry entry data derived from querying 
                            registry changes known for persistence
banking-dns                 Banking Trojan Network Communications
dll-hijacking-dns           Feed contains Domains communicated to by samples 
                            leveraging DLL Sideloading and/or hijacking 
                            techniques
doc-net-com-dns             Document (PDF, Office) Network Communications
downloaded-pe-dns           Samples Downloading Executables Network 
                            Communications
dynamic-dns                 Samples Leveraging Dynamic DNS Providers
irc-dns                     Internet Relay Chat (IRC) Network Communications
modified-hosts-dns          Modified Windows Hosts File Network Communications
parked-dns                  Parked Domains resolving to RFC1918, Localhost 
                            and Broadcast Addresses
public-ip-check-dns         Check For Public IP Address Network Communications
ransomware-dns              Samples communicating with Ransomware Servers
rat-dns                     Remote Access Trojan (RAT) Network Communications
scheduled-tasks             Feed containing scheduled task data observed 
                            during sample execution
sinkholed-ip-dns            DNS entries for samples communicating with a 
                            known dns sinkhole
stolen-cert-dns             DNS Entries observed from samples signed with a 
                            stolen certificate
`)
    flag.PrintDefaults()
}

func main() {
    flag.Usage = usage
    // Date argument -- optional. 
    date := flag.String("date", "", "date to sync intel for")
    flag.Parse()

    args := flag.Args()
    // If there are less than two positional arguments, print usage and exit
    if len(args) < 2 {
        flag.Usage()
        os.Exit(1)
    }

    // The feed to sync from threatgrid
    feed := args[0]
    // The apikey to use while performing the sync
    apiKey := args[1]

    // netClient is an http client struct with which to perform http requests
    netClient := &http.Client{
        // Modifying go's default timeout of 0 is always a good idea
        Timeout: time.Second * 10,
    }

    uri := fmt.Sprintf(base_uri, feed, apiKey)
    // If the default date has been chosen, set the uri to be that of the base uri
    if *date != "" {
        uri = fmt.Sprintf(base_date_uri, feed, *date, apiKey)
    }

    resp, err := netClient.Get(uri)
    if err != nil {
        log.Fatal("Failed to retrieve API output. Check arguments and try again.")
    }

    defer resp.Body.Close()

    var reports []ThreatgridReport

    if resp.StatusCode == 200 {
        bodyBytes, _ := ioutil.ReadAll(resp.Body)
        json.Unmarshal(bodyBytes, &reports)
    }


    fmt.Println(brointel.Headers())
    for _, report := range reports {
        // populate the underlying meta - this shouldn't need to change between 
        // indicators
        meta := brointel.MetaData{feed, report.Description, report.Info, true}
        for _, ip := range report.Ips {
            item := brointel.Item{ip, brointel.ADDR, meta}
            fmt.Println(item.String())
        }
        item := brointel.Item{report.Domain, brointel.DOMAIN, meta}
        fmt.Println(item.String())
        item = brointel.Item{report.SampleMD5, brointel.FILE_HASH, meta}
        fmt.Println(item.String())
        item = brointel.Item{report.SampleSHA256, brointel.FILE_HASH, meta}
    }

    // fmt.Print(reports)
}
