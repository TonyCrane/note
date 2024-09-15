---
counter: True
comment: True
---

# Network Security Assignment

!!! abstract
    网络安全理论作业

    !!! warning "仅供学习参考，请勿抄袭"

## DDoS
### a. What is the difference between DoS attacks and DDoS attacks? 

DoS is Denial of Service Attack, which means that the attacker sends a large number of requests to the target, causing the server to be unable to respond to other normal requests. DDoS is Distributed Denial of Service Attack, which means that the attacker uses a lot of machines to perform a DoS attack on the target. DoS attacks are performed by a single machine, so it is easy to detect and defend against by blocking the IP. DDoS is difficult to detect and it can be more powerful than DoS attacks.

### b. How does the TCP SYN Flood attack work? 

The attacker sends a large number of TCP SYN packets to the target server, the server will respond with a SYN-ACK packet and store the connection information in the buffer and wait for the ACK packet from the client to establish the connection. But if the attacker doesn't respond with the ACK packet, the connection information of the attacker will fill up the server's buffer so that the server can't establish a normal connection will other clients until the old connection info in the buffer is expired.

### c. How does the solution of SYN Cookies against TCP SYN Flood attacks work? 

The main reason that TCP SYN Flood attacks work is that the connection info should be stored in the server's queue to wait for response and remember the connection. The solution of SYN Cookies is to move the connection info from the server's buffer to the packet itself. The server will generate a special SYN-ACK packet with the connection info and send it to the client. When the client sends the ACK packet back, the server will verify the connection info in the packet and establish the connection. This way the server doesn't need to store the connection info in the buffer and the buffer will not be filled up by the attacker.

### d. How does the DNS Amplification Attack work? How to defend against it? 

DNS Amplification Attack uses an open DNS resolver. The attacker pretend itself as the victim by sending query packet with the victim's IP as the source, so that the resolver will send the result to the victim. And if the attacker using the ANY query command, the resolver will send all the records which is very large to the victim, causing a DDoS attack. And the output traffic is much larger than the attacker's input traffic, which is an amplification attack.

To defend against it, we can reduce the number of open DNS resolvers, disable ANY request of the resolvers, disable UDP service of the server, or verify the query packet, etc.

## DDoS
### a. How does Memcached attack work? 

Memcached attack is a kind of amplification attack. The attacker first store some large file in the memcached server, and then send a request to the server with the victim's IP as the source. Then the memcached server will send the large file to the victim, with many requests such as this, the victim will be overwhelmed by the large traffic, causing a DDoS attack.

### b. What is the difference between HTTP Flood and Fragmented HTTP Flood?   

HTTP Flood usually GET or POST some large content from the server, then the server need to take a lot of time to work, such as read or write content to the database. So this will consume the computation resource of the server.

But if it takes too long to respond, the HTTP request will be expired. Fragmented HTTP Flood trys to split the HTTP segment into many fragments, and send it slowly but in the TTL, so the server will keep the connection and be consumed all the time.

### c. Why is Fragmented HTTP Flood relatively more challenging to detect? 

Because Fragmented HTTP Flood Attack just looks like a normal user. Other DDoS attacks usually send a large number of useless packets, or a packet requesting large content to the server, so it is easy to detect. But Fragmented HTTP Flood Attack just keep the connection and send some small packets just as normal, so it is difficult to detect.

### d. How does Ingress Filtering work? 

Ingress Filtering is a method to filter the incoming packets. When the packet go through an AS, the AS will check the packet's source IP address, if the source IP address is not in the range of the AS, meaning that the IP address is spoofed, the packet won't be routed to the destination. This can prevent the IP spoofing attack.

### e. How does IP Traceback work? 

IP Traceback adds more information to the packet to trace the routing path, which allows the receiver to check if the packets are from the correct source. If the packet is from the wrong source, the receiver can drop the packet. This can prevent the IP spoofing attack.

## Secure Routing
### a. What are the key features of the five typical delivery schemes? 

Unicast is to send to a single host. Boardcast sends the packet to all hosts in the same subnet. Multicast sends the packet to a group of hosts. Anycast sends to any one of the hosts in the group. Geocast sends to a group of hosts in a specific geographical area.

### b. What is the framework of the Dijkstra algorithm? 

```
initial the dis array to infinity (except the source node)
repeat until all the nodes are visited:
    find an unvisited node with the smallest dis value
    mark the node as visited
    for each neighbor of the node:
        if the dis of the neighbor is larger than now + the distance between the node and the neighbor:
            update the dis of the neighbor
```

### c. What is the framework of the Bellman-Ford algorithm? 

```
initial the dis array to infinity (except the source node)
repeat until no update is made:
    for each node:
        if dis is inf: continue
        for each neighbor of the node:
            if the dis of the neighbor is larger than now + the distance between the node and the neighbor:
                update the dis of the neighbor
```

### d. How does prefix hijacking work? 

The attacker announces a prefix that is not owned by itself, so the traffic will be routed to the attacker's AS. The attacker can monitor the traffic, or modify the traffic, or drop the traffic, etc. Or the attacker announces that it has a shorter path to a prefix, which will also cause the traffic to be routed to the attacker's AS.

### e. How does RPKI work? Why is it insufficient for secure routing?

RPKI is a method to verify the ownership of the IP address. The owner of the IP address will sign the prefix with its private key, and the router will verify the signature with the public key. If the signature is correct, the router will accept the prefix. So RPKI can avoid prefix hijacking with the attacker announces it is another prefix.

But RPKI is insufficient for secure routing because it can't prevent the prefix hijacking with the attacker announces it has a shorter path to the prefix.

## Anonymous Communication
### a. Why is current Internet communication vulnerable to anonymity or privacy leakage?   

Because the packet need to store source and destinate IP address, so the routers can route the packet to the destination. But the attackers can monitor the packets and infer the source and dest IP, which is vulnerable to anonymity or privacy leakage.

### b. In which scenarios do users require the communication anonymity or privacy as concerned in sub-question a?

When the user wants to hide the source or dest IP address, such as the user wants to visit a website that is blocked by the government, or the user wants to send a message to someone without being monitored and being found, etc.

### c. How to use proxies to secure communication anonymity? What are the possible limitations? 

The user can use a proxy to hide the source IP address. The user sends the packet to the proxy, and the proxy sends the packet to the destination. The destination will only see the proxy's IP address, not the user's IP address. The proxy can also encrypt the packet to protect the content.

But if the attacker monitor the packets between the user and the proxy or the proxy is attacked, the anonymity will also be broken.

### d. How does Onion Routing provide a better guarantee for anonymity? 

Onion Routing is a method to encrypt the packet with multiple layers. The user sends the packet to the first node, the first node will decrypt the first layer and send the packet to the second node, , and so on. The last node will send the packet to the destination. The destination will only see the last node's IP address, not the user's IP address. The nodes can't infer the source and dest IP address unless the attacker has enough number of nodes collude with each other, which is almost impossible in the onion network.

### e. How to infer anonymity or privacy of Onion Routing traffic?

Each node only know the information of the previous node and the next node, so the nodes can't infer the source and dest IP address. Because there are a lot of layers, the node's can't infer whether the dest is the final dest or not. So the anonymity or privacy of Onion Routing traffic is guaranteed.

## Web Security
### a. How does Same Origin Policy work? 

Same Origin Policy is a method to prevent the script from one origin to access the content of another origin. The origin is defined as the protocol, domain, and port. If the script from one origin tries to access the content of another origin, the browser will block the request.

### b. How does SQL Injection work? How to defend against it 

SQL Injection is a method to inject the SQL command into the input field of the website. The attacker can input the SQL command in the input field, and the website will execute the SQL command, which can cause the database to be deleted, or the data to be leaked, etc.

To defend against it, the website can use a blacklist to filter the input, to ensure that the input is safe to use. Or the website can use prepared statement to execute the SQL command, which can prevent the SQL Injection.

### c. Please refer to the slides or search online and provide two concrete examples of SQL Injection.

Use challenge 5 & 6 in lab 3 as examples. In challenge 5, the server will execute query command:

```php
$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
```

And the attacker can first close the quote and then use union to select the password from the table by just input `1' UNION SELECT first_name, password as last_name FROM users WHERE '1'='1` as the id. Then after concatenation, the query command will be like follow which will read the passwords:

```sql
SELECT first_name, last_name FROM users WHERE user_id = '1' UNION SELECT first_name, password as last_name FROM users WHERE '1'='1';
```

In challenge 6, the server will only tell us whether a user exists in the database or not, which means we can only get the result as boolean value. Then we can concatenate the query command to check each char of the password to leak the whole password:

```sql
SELECT first_name, last_name FROM users WHERE user_id = '
crane' OR ascii(substr((SELECT password FROM users LIMIT 0, 1), 1, 1)) = 48
#';
```

Just let the user_id can't be found, and then the result of the query is only depend on the part after `OR` which is to check the first char of the password is '0' or not. Then we can check each char of the password to leak the whole password.

## Email Security
### a. Please describe common threats against Email security. 

- Authentication-related Threats: unauthorized access to email systems
- Integrity-related Threats: unauthorized modification of email content
- Confidential-related Threats: unauthorized disclosure of sensitive information
- Availability-related Threats: prevent end users from being able to send and receive emails

### b. How should an Email be protected to support both Authentication and Confidentiality? 

To support authentication, the sender uses SHA-256 to generate a 256-bit message digest and encrypt the message digest with RSA using the sender's private key, then append the result as well as the signer’s identity to the message. So that the receiver uses RSA with the sender's public key to decrypt, recover, and verify the message digest.

To support Confidentiality, the sender creates a message and a random 128-bit number as a content-encryption key for this message only and encrypt the message using the content-encryption key, then encrypt the content-encryption key with RSA using the receiver's public key and append it to the message. The receiver can use RSA with its private key to decrypt and recover the content-encryption key and use the content-encryption key to decrypt the message.

### c. Please describe the differences among DANE, SPF, and DKIM. 

DANE is based on DNSSEC, it is used to ensure the destination's certification. SPF is part of DNS, which certificate the emails sent from the mail servers in the domain. DKIM is to certificate by signature.

## Traffic Analysis
### a. Please describe the properties of the four types of commonly used Firewall. 

- Packet Filtering Firewall: filter the packet based on the header information
- Stateful Inspection Firewall: check both the packet and its context
- Application Proxy Firewall: a relay of application-level traffic
- Circuit-Level Proxy Firewall: check only a rely of TCP segments

### b. What are the differences among Firewall, IDS, and IPS? 

Firewall limits access to ports by given settings, it can't filter intrusions. IDS will report but not filter the intrusions. IPS can both report and filter the intrusions.

### c. Please list commonly used methods for obfuscating traffic to evade detection?

- Encrypt traffic to hide payloads
- Use proxy to hide entire packets
- Introduce noise traffic to hide patterns

## Open Question - Authentication Efficiency

> Consider a time-consuming authentication scenario where a database records all secret keys of a large number of users. When the system authenticates a user, it first issues a challenge message to the user. The user then uses his/her key to encrypt the challenge and then returns the encrypted challenge to the system. The system then encrypts the challenge using one key in the database after another and compares the result with the received encrypted message. Once a match is found, the system accepts the user. Otherwise, the user is denied. This authentication protocol surely takes a lot of time and computation. 
> 
> Design a possible solution to speed up the authentication process.

To use the same authentication method but in a more fast way. We can also record the users' username or something works like an identifier. When the user send back the encryptd challenge to the system, it should also send its username. Then the server can find it's private key and to authenticate the user.

Then we consider the security of this method, as the server, when using the old method to authenticate, the server will know the private key finally, and as the new method, the server will know the private key at the beginning, they are nothind different. And the we consider that if there is someone monitoring the traffic, the attacker will know the username, but the attacker have nothing to do with the username, it's useless. So the new method is secure.

And there is a more secure method, which is just record the public key of the users, and use public key to decrypt the encrypted challenge and then compare the result as the issued challenge. Using this method, the server won't know the private key of the user, it's more secure.

## SHINE YOUR WAY

> Design a question that you think is feasible as an exam question. 
>

### a. Which topic among the lectures you would like to consider? 

Web Security. More specifically, SQL Injection.

### b. Describe a (sufficiently complex) question; 

There is a website which provide a username parameter in the URL `?username=...`, but the website will not authenticate the user, the username is just to query whether the user exists in the database or not, and then store the result in the log file on the server. So the parameter is useless to the user because there is no response and the user can't see the log file. Try to use SQL Injection to leak the username table in the database.

### c. Provide also a correct sample solution, thanks.

Because there is no response to the user, we can't use normal injections such as boolean based injection. But once access the webpage with username parameter, there will be a query command executed in the server. We can use time based injection, which means if the condition is true, the query will sleep for a while, then we can infer the result from the time the webpage response. One possible exploit is `?id=1' AND IF(..., sleep(5), 1) --+`, then the query will sleep for 5 seconds if the condition is true,.

