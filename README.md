# Yet another arp-spoofing tool
ARP cache poisoning attack implemented in C for fun (and profit ?), using `libpcap`.


## Usage


```
sudo ./arp-spoof <target_ip> <impersonate_ip> <interface_name>

Example:
sudo ./arp-spoof 192.168.1.13 192.168.1.1 eth0
```
Need to run as root because it uses low-level networking capabilities.  

`net.ipv4.ip_forward` must be set to `1`, unless you just want to `DOS` the network between 2 given hosts.  
`sudo sysctl -w net.ipv4.ip_forward=1`

The order of `<target_ip>` and `<impersonate_ip>` doesn't matter.

## Troubleshoot

### Compilation
On kali, I had to create a symbolic link to `libcap.so.1`:

```
# Adapt it to the version of your libpcap.so.1.xxx
ln -s /usr/lib/x86_64-linux-gnu/libpcap.so.1.10.3 /usr/lib/x86_64-linux-gnu/libpcap.so.1
```
### Running
It currently tries to resolve {`target_ip`, `impersonate_ip`} mac address by sending broadcast ARP requests.
Make sure the mac addresses resolved are correct.

## Compilation

```
# Ubuntu / Debian-based
sudo apt install -y libpcap0.8 libpcap0.8-dev
make

# Other
Require libpcap0.8 or newer, then just compile it
```


## TODO
<details>
  <summary>Show todo list</summary>
  
- [ ] cli args
    - [ ] set number of retries for mac addr resolver
    - [ ] NRV mode (without nanosleep + nb thread ?)
    - [ ] Custom tcpdump filter
    - [ ] set mac addr manually in case of resolver don't work ?
    - [ ] save to file

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
