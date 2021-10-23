# Setup

```
sudo apt install libpcap-dev
git clone ...
cd nmap_detect
go build nmap_detect.go
sudo setcap cap_net_raw,cap_net_admin=eip ./nmap_detect
```

# Examples

Begin detection:
```
./nmap_detect -i lo
Interface lo has IP 127.0.0.1
Interface lo has IP ::1
Starting to read packets
```

## IPv4

Port scan:
```
sudo nmap -sV --top-ports 10 127.0.0.1
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-23 02:25 PDT
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000013s latency).

PORT     STATE  SERVICE       VERSION
21/tcp   closed ftp
22/tcp   closed ssh
23/tcp   closed telnet
25/tcp   closed smtp
80/tcp   closed http
110/tcp  closed pop3
139/tcp  closed netbios-ssn
443/tcp  closed https
445/tcp  closed microsoft-ds
3389/tcp closed ms-wbt-server

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.50 seconds
```

Observe detections:
```
SYN to 127.0.0.1:445 from 127.0.0.1
SYN to 127.0.0.1:25 from 127.0.0.1
SYN to 127.0.0.1:139 from 127.0.0.1
SYN to 127.0.0.1:80 from 127.0.0.1
SYN to 127.0.0.1:21 from 127.0.0.1
SYN to 127.0.0.1:22 from 127.0.0.1
SYN to 127.0.0.1:23 from 127.0.0.1
SYN to 127.0.0.1:110 from 127.0.0.1
SYN to 127.0.0.1:3389 from 127.0.0.1
SYN to 127.0.0.1:443 from 127.0.0.1
```

## IPv6

Port scan:
```
sudo nmap -sV --top-ports 10 -6 ::1
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-23 02:25 PDT
Nmap scan report for localhost (::1)
Host is up (0.000017s latency).

PORT     STATE  SERVICE       VERSION
21/tcp   closed ftp
22/tcp   closed ssh
23/tcp   closed telnet
25/tcp   closed smtp
80/tcp   closed http
110/tcp  closed pop3
139/tcp  closed netbios-ssn
443/tcp  closed https
445/tcp  closed microsoft-ds
3389/tcp closed ms-wbt-server

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.51 seconds
```

Observe detections:
```
SYN to ::1:139 from ::1
SYN to ::1:443 from ::1
SYN to ::1:80 from ::1
SYN to ::1:110 from ::1
SYN to ::1:3389 from ::1
SYN to ::1:22 from ::1
SYN to ::1:21 from ::1
SYN to ::1:23 from ::1
SYN to ::1:25 from ::1
SYN to ::1:445 from ::1
```
