# Yet another arp-spoofing tool
ARP cache poisoning attack implemented in C for fun (and profit ?), using `libpcap`.


## Usage


```
sudo ./yaarp-spoof -i <interface> <target_ip1> <target_ip2>

Example:
sudo ./yaarp-spoof -i eth0 192.168.1.13 192.168.1.1
sudo ./yaarp-spoof -i eth0 -o /tmp/output.pcap -f /tmp/filter -r 10 -t 50000 192.168.1.13 192.168.1.37


Usage: yaarp-spoof [OPTION...] -i <interface> <target_ip1> <target_ip2>
ARP cache poisoning attack implemented in C for fun (and profit ?), using
libpcap

  -f, --filter=INFILE        Path to file containing a custom tcpdump filter
  -i, --interface=INTERFACE  Network interface to use
  -o, --output=OUTFILE       Save the capture to a file (affected by filter
                             option)
  -r, --retry=NUMBER         Number of requests sent when trying to resolve
                             targets mac addr (Default = 5)
  -t, --time=DURATION        Time (in ns) between each spoofed ARP requests
                             (Default = 50000)
```
Need to run as root because it uses low-level networking capabilities.  

`net.ipv4.ip_forward` must be set to `1`, unless you just want to `DOS` the network between 2 given hosts.
`sudo sysctl -w net.ipv4.ip_forward=1`

The order of `<target_ip1>` and `<target_ip2>` doesn't matter.

The filter option follow the tcpdump filter format, see `man pcap-filter` or [here](https://www.tcpdump.org/manpages/pcap-filter.7.html).  
The default filter value is: `not arp and (host <target_ip1> or host <target_ip2>)` to have only intercepted traffic.

In this current state (v0.2), I strongly recommend using `-o output.pcap` to perform post-analysis, as the parser is WIP.

## Troubleshoot

### Compilation
On kali, I had to create a symbolic link to `libcap.so.1`:

```
# Adapt it to the version of your libpcap.so.1.xxx
ln -s /usr/lib/x86_64-linux-gnu/libpcap.so.1.10.3 /usr/lib/x86_64-linux-gnu/libpcap.so.1
```
### Running
It currently tries to resolve {`target_ip1`, `target_ip2`} mac address by sending broadcast ARP requests.
Make sure the mac addresses resolved are correct.

## Compilation

```
# Ubuntu / Debian-based
sudo apt install -y libpcap0.8 libpcap0.8-dev
make

# Other (not tested)
Require libpcap0.8 or newer, then just compile it
```


## TODO
<details>
  <summary>Show todo list</summary>
  
- cli args
    - [x] set number of retries for mac addr resolver
    - [x] NRV mode (without nanosleep + nb thread ?)
    - [x] Custom tcpdump filter
    - [x] save to file
    - [ ] (?) set mac addr manually in case of resolver don't work

- Packet parser
    - [ ] Implement protocol recognition
    - [ ] Print payload only
    - [ ] Clean output
    - [ ] (?) Interactive mode

- MISC
    - [ ] Better proper cleanup when SIGINT
    - [ ] Review dynamic memory allocation
    - [ ] Running / Tested on *BSD
    - [ ] Static compilation

</details>

# Author
Vlad Rico ([@RicoVlad](https://twitter.com/RicoVlad))

# Reference
- [Wikipedia](https://en.wikipedia.org/wiki/ARP_spoofing)
- [RFC 826](https://datatracker.ietf.org/doc/html/rfc826)

## Disclaimer
This project was created only for learning purpose.
Usage of this tool to attack targets without prior mutual consent is illegal.
It is the end user's responsibility to obey all applicable local, state and federal laws.
Developers assume no liability and are not responsible for any misuse or damage caused by this program.
