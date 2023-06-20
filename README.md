# Network Namespace

Linux kernal (v5.6) has 8 types of namespaces. Network namespace is one of the feature of linux kernal.
Most container technologies use this feature to create isolated  network stack in the operating system. We can create virtualized network stack with its interfaces, IP range, routing table etc. We can run application in different network stacks.

*VETH* devices are virtual ethernet devices. They can act as tunnels between network namespaces to create a bridge to a physical network device in another namespace, but can also be used as standalone network devices. The virtual ethernet device will act as a tunnel between the network namespaces that we will create.

We will go thorugh linux network namespace. We want to learn how two network namespace communicate with each other. Also we will see how a network namespace will communicate with outer world.

Our objectives:
 - Create two network namespace and establish communication between them
 - Add a bridge network device and communicate two/multiple network namespaces via bridge
 - Namespace to root/default namespace communication via bridge
 - Make a communication with outside world via bridge


## Section 01:

Create network namespace

```sh
> sudo ip netns add earth
> sudo ip netns add neptune
```

We have created two different namespace, and its like two different computer.
To check the list.
```sh
> sudo ip link

earth
neptune
```


![two-name-space](https://user-images.githubusercontent.com/17932841/202871754-1256482d-86b1-492d-ab51-ec9091ee0d7e.jpeg)



Now we will add a virtual ethernet peer between this two namespace.

```sh
> sudo ip link add earth-veth type veth peer name neptune-veth
```
We created a peer but it's not assigned to any network namespace. Lets assign them. We will assign `earth-veth` to `earth` namespace and another end to `neptune` namespace.

```sh
> sudo ip link set earth-veth netns earth
> sudo ip link set neptune-veth netns neptune
```

Lets have a look at the earth network namespace

```sh
> sudo ip netns exec earth ip addr

1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
4: earth-veth@if3: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 26:61:7a:32:8a:72 brd ff:ff:ff:ff:ff:ff link-netnsid 1
```

> When we want to run a command inside a network namespace we can execute our command like this: ip netns exec <net ns name> command or ip -n <net ns name> command

The `earth` namespace has two ethernet devices, `lo` and `earth-veth`. Check `neptune` namespace also.
`lo` is a loopback device. You can imagine it as a virtual network device that is on all systems, even if they aren't connected to any network. And `earth-veth` is our newly created device.
If we check the state they are in `DOWN` state. Lets up those.

```sh
> sudo ip netns exec earth ip link set dev earth-veth up
> sudo ip netns exec earth ip link set dev lo up
```

Run same command in `neptune` namespace
```sh
> sudo ip netns exec neptune ip link set dev neptune-veth up
> sudo ip netns exec neptune ip link set dev lo up
```


Lets check again
```sh
> sudo ip netns exec earth ip addr

1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
4: earth-veth@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 26:61:7a:32:8a:72 brd ff:ff:ff:ff:ff:ff link-netnsid 1
    inet6 fe80::2461:7aff:fe32:8a72/64 scope link
       valid_lft forever preferred_lft forever
```

Now `earth-veth` state is `UP`, check same thing from `neptune` namespace there `neptune-veth` state is `UP`.

Our virtual interfaces are enable but see they don't have any IP addresses, without IP addresses they can't talk with each other. Lets assign IP address to them.

```sh
> sudo ip netns exec earth ip addr add 10.10.0.10/16 dev earth-veth
> sudo ip netns exec neptune ip addr add 10.10.0.20/16 dev neptune-veth
```

Our setup is like this:

![namespaces-connected (1)](https://user-images.githubusercontent.com/17932841/202871732-7650d391-012c-41d8-9b22-84a7ef6c2e02.jpeg)


At this stage if we want to talk between this two namespace, packets will drop. Because they don't have any route so they don't know where the packet will forward. Add route within them.

```sh
> sudo ip netns exec earth ip route add default via 10.10.0.10 dev earth-veth
> sudo ip netns exec neptune ip route add default via 10.10.0.20 dev neptune-veth
```

Let test, can they talk with each other?

```sh
> sudo ip netns exec earth ping 10.10.0.20

PING 10.10.0.20 (10.10.0.20) 56(84) bytes of data.
64 bytes from 10.10.0.20: icmp_seq=1 ttl=64 time=0.018 ms
64 bytes from 10.10.0.20: icmp_seq=2 ttl=64 time=0.031 ms
64 bytes from 10.10.0.20: icmp_seq=3 ttl=64 time=0.031 ms
^C
--- 10.10.0.20 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2089ms
rtt min/avg/max/mdev = 0.018/0.026/0.031/0.008 ms
```

From neptune namespace
```sh
> sudo ip netns exec neptune ping 10.10.0.10

PING 10.10.0.10 (10.10.0.10) 56(84) bytes of data.
64 bytes from 10.10.0.10: icmp_seq=1 ttl=64 time=0.041 ms
64 bytes from 10.10.0.10: icmp_seq=2 ttl=64 time=0.049 ms
64 bytes from 10.10.0.10: icmp_seq=3 ttl=64 time=0.041 ms
^C
--- 10.10.0.10 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2041ms
rtt min/avg/max/mdev = 0.041/0.043/0.049/0.008 ms
```

YES !!! It's working, they can talk with each other based on IP routing table.

```sh
> sudo ip netns exec earth ip route

10.10.0.0/16 dev earth-veth proto kernel scope link src 10.10.0.10
```

ARP table
```sh
> sudo ip netns exec earth

Address                  HWtype  HWaddress           Flags Mask            Iface
10.10.0.20          ether   12:6c:8c:49:15:2c   C                     earth-veth

> sudo ip netns exec neptune

Address                  HWtype  HWaddress           Flags Mask            Iface
10.10.0.10          ether   26:61:7a:32:8a:72   C                     neptune-veth
```


Lets try to ping `earth` namespace IP from default network namespace (host namespace)

```sh
> ping 10.10.0.10

PING 10.10.0.10 (10.10.0.10): 56 data bytes
Request timeout for icmp_seq 0
Request timeout for icmp_seq 1
Request timeout for icmp_seq 2
Request timeout for icmp_seq 3
^C
--- 10.10.0.10 ping statistics ---
5 packets transmitted, 0 packets received, 100.0% packet loss
```
 It's not working because default network namespace don't know this ip, there are no routing between default and earth or neptune namespace.

Delete current namespaces and move to our next step.

```sh
> ip netns delete earth
> ip netns delete neptune
```



## Section 02:

Till now we have go through basic network namespace fundamentals where two network namespace can talk with each other.
Now if we need to connect three or more namespaces in the same machine, then in our earlier method we have to hardcoded connection in between namespaces.
In this situation we need  **switch** between namespaces. A “switch” in the networking world is a device which makes communication between devices in a “transparent” fashion by creating a dedicated logical link between ports. The “switch” inside a linux virtual machine is often referred to as a “linux bridge”
A bridge network is a Link Layer device which forwards traffic between network segments. A bridge can be a hardware device or a software device running within a host machine’s kernel.
So, we need a virtual networking bridge. We will create two network namespace (we can create multiple here also) and a virtual bridge device (it will act as a network switch).

 
Lets create namespace, virtual ethernet cable, assign IP to them. Like we did earlier. We will create two namespace for this demonstration but we can do this with multiple namespaces.

```sh
> sudo ip netns add earth
> sudo ip netns add neptune
> sudo ip link add earth-veth type veth peer name earth-br-veth
> sudo ip link add neptune-veth type veth peer name neptune-br-veth
```


Add veth device to namespaces

```sh
> sudo ip link set earth-veth netns earth
> sudo ip link set neptune-veth netns neptune
> sudo ip netns exec earth ip addr add 10.10.0.10/16 dev earth-veth
> sudo ip netns exec neptune ip addr add 10.10.0.20/16 dev neptune-veth
```


Here we have connected one side of the veth to a namespace but otherside is still not connected to any namespace. Those other two side we will connect them to bridge device.

Create a bridge device and connect those to bridge.

```sh
> sudo ip link add planet-br type bridge
> sudo ip link set earth-br-veth master planet-br
> sudo ip link set neptune-br-veth master planet-br
```

The setup looks like this

 
![namespace-with-bridge](https://user-images.githubusercontent.com/17932841/202871961-133d8370-23af-4bf5-aaac-9a734ea6849f.jpeg)


We have to up all of the virtual devices to connect.

```sh
> sudo ip link set planet-br up
> sudo ip link set earth-br-veth up
> sudo ip link set neptune-br-veth up
> sudo ip netns exec earth ip link set dev lo up
> sudo ip netns exec earth ip link set dev earth-veth up
> sudo ip netns exec neptune ip link set dev lo up
> sudo ip netns exec neptune ip link set dev neptune-veth up
```

Now all devices are up. You can check their status run `ip addr` command in those namespace.
Lets try to ping between the two namespaces:

```sh
> sudo ip netns exec earth ping 10.10.0.20 -c1

PING 10.10.0.20 (10.10.0.20) 56(84) bytes of data.
64 bytes from 10.10.0.20: icmp_seq=1 ttl=64 time=0.076 ms

--- 10.10.0.20 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms

> sudo ip netns exec neptune ping 10.10.0.10 -c1

PING 10.10.0.10 (10.10.0.10) 56(84) bytes of data.
64 bytes from 10.10.0.10: icmp_seq=1 ttl=64 time=0.107 ms

--- 10.10.0.10 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.107/0.107/0.107/0.000 ms
```
> with `-c1` command it will transmit 1 packet only

Notice one thing here, we didn't add any default route here but still its working because of bridge involved here. Check route inside of the namespace there already route added and also ARP is populated.

```sh
> sudo ip netns exec earth ip route

10.10.0.0/16 dev earth-veth proto kernel scope link src 10.10.0.10

> sudo ip netns exec earth arp

Address                  HWtype  HWaddress           Flags Mask            Iface
10.10.0.20            ether   3e:a6:7c:d7:d7:b9   C                     earth-veth
```

Okay, two namespaces can communicate with each other. Can default/root network namespace can communicate with those namespaces?

```sh
> ping 10.10.0.10 -c1

PING 10.10.0.10 (10.10.0.10) 56(84) bytes of data.

--- 10.10.0.10 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms
```

So it's not working because there is no routing between host/root namespace and those two namespace.

## Section 03

#### _earth_ namespace to host namespace communication
  
  ![namspace-with-bridge-ip](https://user-images.githubusercontent.com/17932841/202872120-edbf6581-b6fe-44be-8604-97f96e726327.jpeg)


Here we want to stablish a communication between `earth` or `neptune` namespace to root/host namespace via bridge virtual device. Bridge will work as a gateway.

In our case `192.168.0.108` IP address is assigned to eth0 of host namespace

```sh
> ip addr show 

eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:0e:82:b9 brd ff:ff:ff:ff:ff:ff
    inet 192.168.0.108/24 brd 192.168.0.255 scope global dynamic noprefixroute enp0s3
       valid_lft 5658sec preferred_lft 5658sec
    inet6 fe80::aa79:2130:6242:699/64 scope link noprefixroute
       valid_lft forever preferred_lft forever
```

Ping this root namespace ip from earth namespace

```sh
> sudo ip netns exec earth ping 10.10.0.112 -c1

connect: Network is unreachable
```

This error is expected, check route

```sh
> sudo ip netns exec earth route

Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
10.10.0.100       0.0.0.0         255.255.0.0     U     0      0        0 e-v
```

We got the issue, the host IP doesn't have any route table entry in earth namespace. He don't know this IP and can't eastablish a connection.
So we need to add a default gateway so that which IP addresses are not matching they forward via bridge device (planet-br).
We didn't assign any ip to our bridge (`planet-br`). First add am IP and then add default gateway to earth and neptune namespace.

```sh
> sudo ip addr add 10.10.0.1/16 dev planet-br
> sudo ip netns exec earth ip route add default via 10.10.0.1
> sudo ip netns exec neptune ip route add default via 10.10.0.1
```

Check route

```sh
> sudo ip netns exec earth route

Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         10.10.0.1       0.0.0.0         UG    0      0        0 ev
10.10.0.0       0.0.0.0         255.255.0.0     U     0      0        0 ev
```


Lets test again

```sh
> sudo ip netns exec earth ping 192.168.0.108 -c1

PING 192.168.0.108 (192.168.0.108) 56(84) bytes of data.
64 bytes from 192.168.0.108: icmp_seq=1 ttl=64 time=0.105 ms

--- 192.168.0.108 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.105/0.105/0.105/0.000 ms
```

Wahhh !!! its working. Now we can communicate between earth or neptune namespace with host namespace.

Lets move outside of the box. Till now we have eastablished connection between two namespaces and then eastablished connection with host/root namespace. Can this namespace (earth or neptune) can eastablish connection with any outside world. We want to connect them with internet. We will ping google IP (8.8.8.8) from earth and neptune nametune.


## Section 04

#### _earth_ namespace to internet communication

  
  ![namespace-to-internet-connection](https://user-images.githubusercontent.com/17932841/202872154-f7c42e7a-0004-48e8-8969-e85f847116b7.jpeg)

  
  
Lets ping `8.8.8.8` from earth namespace

```sh
> sudo ip netns exec earth ping 8.8.8.8 -c1

PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.

--- 8.8.8.8 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms
```

The response is different here, its not like Network is unreachable but it seems that the packet is stuck somewhere, we have to find where the packet get stuck. To debug packet flow we have a very useful tool called *tcpdump*, a powerful comman-line packet analyzer.

In our scenario, ping command goes from earth interface to host via planet-br. So first lets debug from `planet-br`, does the packet came here.

run ping command from earth namespace as we did earlier and in a new ssh session run this command from host

```sh
> sudo tcpdump -i planet-br icmp

tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on planet-br, link-type EN10MB (Ethernet), capture size 262144 bytes
13:54:26.471001 IP 10.10.0.10 > dns.google: ICMP echo request, id 2197, seq 1, length 64
13:54:27.481254 IP 10.10.0.10 > dns.google: ICMP echo request, id 2197, seq 2, length 64
13:54:28.504693 IP 10.10.0.10 > dns.google: ICMP echo request, id 2197, seq 3, length 64
```

Looks like `planet-br` is receiving the packets so lets debug our host `eth0` interface.

```sh
> sudo tcpdump -i eth0 icmp

tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on enp0s3, link-type EN10MB (Ethernet), capture size 262144 bytes
^C
0 packets captured
0 packets received by filter
0 packets dropped by kernel
```

hmmm.... packets are not reaching to `eth0`. But why?
Okay found an issue, IP forwarding is disabled.

```sh
> sudo vi /proc/sys/net/ipv4/ip_forward
```

Change the value 0 to 1 and save it.

We can use the following sysctl command to enable or disable Linux IP forwarding on our system. Keep in mind that this setting is changed instantly at runtime. Also, the result will not be preserved after rebooting the system.
```sh
# to disable
> sudo sysctl -w net.ipv4.ip_forward=0
# to enable
> sudo sysctl -w net.ipv4.ip_forward=0
```

Check the `eth0` interface again (make sure ping command is running)

```sh
> sudo tcpdump -i eth0 icmp

tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on enp0s3, link-type EN10MB (Ethernet), capture size 262144 bytes
14:17:47.367679 IP 10.10.0.10 > dns.google: ICMP echo request, id 2287, seq 1, length 64
14:17:48.377826 IP 10.10.0.10 > dns.google: ICMP echo request, id 2287, seq 2, length 64
14:17:49.400595 IP 10.10.0.10 > dns.google: ICMP echo request, id 2287, seq 3, length 64
```

Finally `eth0` is recieving the packets but hold on packet is still stuck in earth interface. See tcpdump is only getting request logs but there are no reply logs here. From above we saw that packets is tring to reach google dns with private ip address `10.10.0.10`.
For private ip address google dns server can't reach back to earth interface beacuse same private ip address can use million of devices. So we need a public ip to reach to google dns.
Here comes Network Address Translation (NAT), this will convert our private ip to public ip (in our case it will use ISP public ip). We need to add a Source NAT (SNAT) rule in the POSTROUTING chain.

```sh
> sudo iptables --table nat -A POSTROUTING -s 10.10.0.0/16 ! -o planet-br -j MASQUERADE
```

> MASQUERADE hides everything “behind” the host. You’d do that to supply Internet to multiple hosts when you only have one uplink IP address. This tech is used on most consumer-grade Internet access routers, dubbed “NAT”. ([MASQUERADE](https://superuser.com/a/935988))

So we added a SNAT rule, its appending (-a) POSTROUTING rule and action(-j) is MASQUERADE where source (-s) network is 10.10.0.0/16 via planet-br output (-o).

Now lets ping again

```sh
> sudo ip netns exec earth ping 8.8.8.8 -c3

PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=116 time=33.4 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=116 time=33.7 ms
64 bytes from 8.8.8.8: icmp_seq=3 ttl=116 time=35.0 ms

--- 8.8.8.8 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2004ms
rtt min/avg/max/mdev = 33.405/34.077/35.045/0.717 ms
```

Wuuhuu...... we finally did it. Now we are able to communicate with outside world.


Now lets move a step ahead. We will run a server in earth namespace and we will try to access that from outside.
Run a simple server http server using python that is listening on port 8000.

```sh
> sudo ip netns exec earth python3 -m http.server --bind 10.10.0.10 8000

Serving HTTP on 10.10.0.10 port 8000 (http://10.10.0.10:8000/) ...
```

Check can we access this from host, open a new session and run this.

```sh
> telnet 10.10.0.10 8000

Trying 10.10.0.10...
Connected to 10.10.0.10.
Escape character is '^]'.
```

Its connected, check using curl 

```sh
> curl 10.10.0.10:8000
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>Directory listing for /</title>
</head>
<body>
<h1>Directory listing for /</h1>
<hr>
<ul>
<li><a href=".bash_history">.bash_history</a></li>
<li><a href=".cache/">.cache/</a></li>
<li><a href=".config/">.config/</a></li>
<li><a href=".dmrc">.dmrc</a></li>
<li><a href=".gconf/">.gconf/</a></li>
<li><a href=".gnupg/">.gnupg/</a></li>
<li><a href=".local/">.local/</a></li>
<li><a href=".mozilla/">.mozilla/</a></li>
<li><a href="Desktop/">Desktop/</a></li>
<li><a href="Documents/">Documents/</a></li>
<li><a href="Downloads/">Downloads/</a></li>
<li><a href="Music/">Music/</a></li>
<li><a href="Pictures/">Pictures/</a></li>
<li><a href="Public/">Public/</a></li>
<li><a href="sudo">sudo</a></li>
<li><a href="Templates/">Templates/</a></li>
<li><a href="Videos/">Videos/</a></li>
</ul>
<hr>
</body>
</html>
```

Nice we got the response that means our http server is running and listening on port 8000.

Lets try to access this url from browser. In our case, virtual box ip address is `192.168.0.108`, so we will hit the url `http://192.168.0.108:8000/` from web browser.



![Screenshot 2022-11-20 at 3 33 57 AM](https://user-images.githubusercontent.com/17932841/202872409-0a3fb1ff-8fdd-4f99-b6cb-a92ee7c9010f.png)



hmmm... its not accessible from browser. We need to add destination ip nat (DNAT) like we did previously SNAT to ping into google dns

```sh
> sudo iptables --table nat -A PREROUTING -d 192.168.0.108 -p tcp -m tcp --dport 8000 -j DNAT --to-destination 10.10.0.10:8000
```

meaning, any request mathched (-m) tcp in destination (-d) ip 192.168.0.108 (eth0 ip) with destination port (-dport) 8000 will jump (-j) in DNAT rule to the destination 10.10.0.10:8000

We can add port forwarding rule here as well like

```sh
> sudo iptables --table nat -A PREROUTING -d 192.168.0.108 -p tcp -m tcp --dport 3000 -j DNAT --to-destination 10.10.0.10:8000
```

So it will forward `192.168.0.108:3000` to `10.10.0.10:8000`

Lets try againg from browser.



![Screenshot 2022-11-19 at 4 17 02 PM](https://user-images.githubusercontent.com/17932841/202872336-d9107e9e-d27d-43bc-99a2-42c83bb0a0bd.png)



Yaaaaaaa... We did it. We have configured ingress and egress traffic flow.
Congratulations..!!!

To summarize we basically looked at how namespaces are used to create isolation on the same machine and how the linux bridge and iptables is used to forward and masquerade packets to enable communications to the outside world.




### Resources

* Tcpdump -> https://hackertarget.com/tcpdump-examples/
* IPTables -> https://medium.com/skilluped/what-is-iptables-and-how-to-use-it-781818422e52
* NAT -> https://whatismyipaddress.com/nat
* Newwork Namespace -> https://blog.scottlowe.org/2013/09/04/introducing-linux-network-namespaces/
* Newwork Namespace -> https://blogs.igalia.com/dpino/2016/04/10/network-namespaces/
* https://www.gilesthomas.com/2021/03/fun-with-network-namespaces
* https://itnext.io/create-your-own-network-namespace-90aaebc745d
* https://medium.com/@abhishek.amjeet/container-networking-using-namespaces-part1-859d317ca1b8
* https://adil.medium.com/container-networking-under-the-hood-network-namespaces-6b2b8fe8dc2a
* https://iximiuz.com/en/posts/container-networking-is-simple/
* https://www.suse.com/c/rancher_blog/introduction-to-container-networking/
