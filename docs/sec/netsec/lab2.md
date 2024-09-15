---
counter: True
comment: True
---

# Network Security Lab 2

!!! abstract
    网络安全 lab2 实验报告

    !!! warning "仅供学习参考，请勿抄袭，请勿用于非法用途，一切后果与本人无关"

## Goal

> Lab 02 aims to understand the principle of ARP deception and DNS deception, and practice these attacks through tools such as WinCap and Cain.
>
> \*but due to the instruction of TAs, we actually use dsniff tools to perform ARP and DNS deception.

## Steps
### Setup vm and IP

I use macOS as host machine, and use Parallels Desktop as the virtual machine application. And I have installed Ubuntu 22.04 server in the virtual machine.

Parallels Desktop recommends to use "shared network" mode, but in this mode I found that the host can't ping the gateway of the bridge interface, and the attack also won't effect the host's network. So I turn to "bridged network" mode to use the same WiFi network as the host.

After turn down the IPv6 on macOS, the vm can access the network using IPv4. Then we can find the IP address of the host and vm through `ifconfig` command

<div style="text-align: center;">
<img src="/assets/images/sec/netsec/lab2/vm_ip.png" width="80%" style="margin: 0 auto;">
</div>

And in the host:

```text
❯ ifconfig
...
en0: flags=8b63<UP,BROADCAST,SMART,RUNNING,PROMISC,ALLMULTI,SIMPLEX,MULTICAST> mtu 1500
    options=400<CHANNEL_IO>
    ether 88:66:5a:0c:09:90
    inet 172.20.10.2 netmask 0xfffffff0 broadcast 172.20.10.15
    inet6 fe80::8c0:a128:18ee:a8c6%en0 prefixlen 64 secured scopeid 0x7
    nd6 options=201<PERFORMNUD,DAD>
    media: autoselect
    status: active
...
```

And we can find the gateway and dns server using `netstat -rn` and `scutil --dns` command in the host:

```text
❯ netstat -rn
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            172.20.10.1        UGScg                 en0
...

❯ scutil --dns
DNS configuration

resolver #1
  nameserver[0] : 172.20.10.1
  if_index : 7 (en0)
  flags    : Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

...

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 172.20.10.1
  if_index : 7 (en0)
  flags    : Scoped, Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)
```

So we can know that the host's ip at this interface is `172.20.10.2`, the gateway and DNS server is `172.20.10.1`, the vm's ip is `172.20.10.6` and the host and vm can ping each other:

<div style="text-align: center;">
<img src="/assets/images/sec/netsec/lab2/ping.png" width="80%" style="margin: 0 auto;">
</div>

### ARP Spoofing

First check the ARP table of the host:

```text
❯ arp -a
...
? (172.20.10.1) at 62:57:c8:17:26:64 on en0 ifscope [ethernet]
? (172.20.10.2) at 88:66:5a:c:9:90 on en0 ifscope permanent [ethernet]
? (172.20.10.6) at 0:1c:42:ae:51:ae on en0 ifscope [ethernet]
```

Mainly focus on the interface en0, with ip 172.20.10.(1|2|6).

Then run `arpspoof` command in the vm to perform ARP spoofing to the host's gateway:

<div style="text-align: center;">
<img src="/assets/images/sec/netsec/lab2/arping.png" width="80%" style="margin: 0 auto;">
</div>

We can see that the vm is replying host with wrong MAC address which point to itself. So then 172.20.10.1's MAC address will point to the vm:

<div style="text-align: center;">
<img src="/assets/images/sec/netsec/lab2/arp.png" width="80%" style="margin: 0 auto;">
</div>

We can see that the MAC address of 172.20.10.1 is successfully modified to `0:1c:42:ae:51:ae` which is the same as 172.20.10.6.

### DNS Spoofing

With the `arpspoof` running, we can run `dnsspoof` at the same time to reply wrong DNS result. Write `10.10.10.3 *.baidu.com` to `dnsspoof.hosts` and then run `dnsspoof`:

```text
❯ sudo dnsspoof -i enp0s5 -f dnsspoof.hosts host 172.20.10.2 and udp port 53
dnsspoof: listening on enp0s5 [host 172.20.10.2 and udp port 53]
```

Then `ping www.baidu.com` in the host, we can find that the ip address of www.baidu.com is resolved to 10.10.10.3:

<div style="text-align: center;">
<img src="/assets/images/sec/netsec/lab2/dns.png" width="80%" style="margin: 0 auto;">
</div>

And we can find a DNS log of `dnsspoof`:

```text
❯ sudo dnsspoof -i enp0s5 -f dnsspoof.hosts host 172.20.10.2 and udp port 53
dnsspoof: listening on enp0s5 [host 172.20.10.2 and udp port 53]
172.20.10.2.62144 > 172.20.10.1.53:  17469+ A? www.baidu.com
```

So the ARP spoofing attack and DNS spoofing attack is succeed.