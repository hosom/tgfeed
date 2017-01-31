# tgfeed
Tool for pulling threatgrid curated feeds down for Bro


```
Usage: ./tgfeed [OPTIONS] feed_name api_key
Possible Feed Values
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
  -date string
        date to sync intel for
```

## Sample Usage

```
./tgfeed downloaded-pe-dns apikey
#fields indicator       indicator_type  meta.source     meta.desc       meta.url        meta.do_notice
184.68.109.253  Intel::ADDR     downloaded-pe-dns       DNS response information from requests made by samples downloading PE executables.      https://panacea.threatgrid.com/feeds/downloaded-pe-dns/domains/c2.malwaremonkey.space   T
c2.malwaremonkey.space  Intel::DOMAIN   downloaded-pe-dns       DNS response information from requests made by samples downloading PE executables.      https://panacea.threatgrid.com/feeds/downloaded-pe-dns/domains/c2.malwaremonkey.space   T
7dac444a8b3a6a5272690075fdde41e6        Intel::FILE_HASH        downloaded-pe-dns       DNS response information from requests made by samples downloading PE executables.      https://panacea.threatgrid.com/feeds/downloaded-pe-dns/domains/c2.malwaremonkey.space   T
184.68.109.253  Intel::ADDR     downloaded-pe-dns       DNS response information from requests made by samples downloading PE executables.      https://panacea.threatgrid.com/feeds/downloaded-pe-dns/domains/pinocchio.duckdns.org    T
pinocchio.duckdns.org   Intel::DOMAIN   downloaded-pe-dns       DNS response information from requests made by samples downloading PE executables.      https://panacea.threatgrid.com/feeds/downloaded-pe-dns/domains/pinocchio.duckdns.org    T
7dac444a8b3a6a5272690075fdde41e6        Intel::FILE_HASH        downloaded-pe-dns       DNS response information from requests made by samples downloading PE executables.      https://panacea.threatgrid.com/feeds/downloaded-pe-dns/domains/pinocchio.duckdns.org    T
52.203.142.226  Intel::ADDR     downloaded-pe-dns       DNS response information from requests made by samples downloading PE executables.      https://panacea.threatgrid.com/feeds/downloaded-pe-dns/domains/otdelfromcomerceuastatistic.ru   T
52.34.184.219   Intel::ADDR     downloaded-pe-dns       DNS response information from requests made by samples downloading PE executables.      https://panacea.threatgrid.com/feeds/downloaded-pe-dns/domains/otdelfromcomerceuastatistic.ru   T
otdelfromcomerceuastatistic.ru  Intel::DOMAIN   downloaded-pe-dns       DNS response information from requests made by samples downloading PE executables.      https://panacea.threatgrid.com/feeds/downloaded-pe-dns/domains/otdelfromcomerceuastatistic.ru   T
6dc8a329fb048a1d0d53c699879971c8        Intel::FILE_HASH        downloaded-pe-dns       DNS response information from requests made by samples downloading PE executables.      https://panacea.threatgrid.com/feeds/downloaded-pe-dns/domains/otdelfromcomerceuastatistic.ru   T
52.203.142.226  Intel::ADDR     downloaded-pe-dns       DNS response information from requests made by samples downloading PE executables.      https://panacea.threatgrid.com/feeds/downloaded-pe-dns/domains/donbassnoloveukraine.com T
52.34.184.219   Intel::ADDR     downloaded-pe-dns       DNS response information from requests made by samples downloading PE executables.      https://panacea.threatgrid.com/feeds/downloaded-pe-dns/domains/donbassnoloveukraine.com T
donbassnoloveukraine.com        Intel::DOMAIN   downloaded-pe-dns       DNS response information from requests made by samples downloading PE executables.      https://panacea.threatgrid.com/feeds/downloaded-pe-dns/domains/donbassnoloveukraine.com T
6dc8a329fb048a1d0d53c699879971c8        Intel::FILE_HASH        downloaded-pe-dns       DNS response information from requests made by samples downloading PE executables.      https://panacea.threatgrid.com/feeds/downloaded-pe-dns/domains/donbassnoloveukraine.com T
```
