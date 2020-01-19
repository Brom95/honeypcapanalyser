# honeypcapanalyser
python3 script for creating simple honeypot report from pcap files
```
optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        pcap file or dirrectory with files
  -e [E [E ...]]        exclude ip
  -l L                  results limit
```
Result example:
```
118.130.103.212 49567
Organisation: None
Country: KR
Address: Jeollanam-do Naju-si Jinheung-gil Seoul Yongsan-gu Hangang-daero 32 Seoul Yongsan-gu Hangang-daero 32 LG UPLUS
	 20445 49567

122.3.25.50 47039
Organisation: None
Country: PH
Address: Philippine Long Distance Telephone Company 6/F Innolab Building Boni Avenue, Mandaluyong City Philippines 6/F Innolab Building, Boni Avenue, Mandaluyong City PLDT Co., 3/F MGO Bldg., Legaspi cor Dela Rosa Sts., Makati City
	 20445 47039

```
