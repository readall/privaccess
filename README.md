# privaccess
This is a Single packet authentication and authorization server.
There is a client needed and one such implementation is https://github.com/readall/privclient

## ** Currently The code is not suitable for public consumption ** 
## ** That is why server itself is a no-op other than logging the parameters and message from client **

#Introduction
For people who self host service in cloud mostly for consumption of self, friends and family.
The challange is comes from the security aspects such as dyanmic ip address of end devices. 
So if you want to limit the access even using a firewall, it is difficult to set up rules.

# What should be the default access policy on firewall?
Most common answer is "DENY" and then create a small exception rule. This is what will solve our problem.
Banning IP address on repeated failure still leaves a target surface for attack vectors.
Applying default DENY rule is a challange if your home and other devices have dynamic IP address. 
One of the solutions is to implement port-knocking. 

# Port knocking, what is it, what is the drawback
Port knocking is a mechanism in which clients desiring access to server send packets to pre-arranged sequence of ports. 
The server then opens the desired service ports for clients public ip address.
The draw back in simplistic implementation, packet replay and MITM attacks will very easily bypass the defence.

# SPA (Single packet Authorization)
While similar to port-knocking, SPA sends a an encrypted, HMAC payload. 
Encryption prevents exposure of contents to entire world.
HMAC inside encrypted payload provides verification capability for the payload.
The payload contains timestamp, id, and other parameters which makes authenticating the client possible.

# How to configure this?
Currently through conf.toml
config via env variables and other methos is in pipeline.

Currently it is more like a demo and prime use is to let me learn bit more rust.
I wrote this code to experiment with rust and its networking capabilities. At the same time I am using a version of this to protect some services I host.

