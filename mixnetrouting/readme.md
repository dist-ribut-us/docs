## Serverless and Stateless Mixet Routing

### Abstract

This paper makes a case for serverless and stateless mixnet routing. It explores
techniques and advantages of this approach and will describe two methods, one
using an original cipher.

Demo code is provided for both approaches. The demos are presented as unit
tests.

### Argument

Most approaches to mixnets use either servers or dedicated routing nodes, which
behave like servers (they are providing a routing service). In addition to this,
some (most notably TOR) are not stateless. It will be argued that there is
value to a serverless and stateless mixnet.

#### Serverless

This paper will use the term server to mean a consistently available service at
a fixed address. Having servers or server-like-nodes means that the network cap
is set by the capacity of those nodes. The number of nodes and their total
capacity is based on goodwill or ulterior motives.

The relatively static nature of these nodes makes it easier for an adversary to
reduce the effectiveness of the network by controlling a portion of the network
and executing traffic analysis and timing attacks. For example, knowing a
network has 6,300 routing nodes with a total bandwidth capacity 32GB/s means an
adversary would need to add 630 nodes with 5.1MB/s of bandwidth each to control
10% of the traffic.

This network cap also limits the growth of the network to the amount of
resources that are donated to keep the network growing. If most users began
accessing search engines and social media through the current mixnets, they
would be quickly overwhelmed And the capacity can be overwhelmed with a DOS
attack.

#### Peer Routing

Instead of using servers, the network will require that all peers on the network
behave as routing nodes. This spreads the traffic evenly. It means that in order
to control a portion of the network, an attacker must have resources
proportional to the entire network population, not just the server resources
dedicated to the network.

Because all nodes are constantly routing, it becomes very difficult to identify
where a message starts and where it ends - even to an attacker that can inspect
all network traffic. If a message enters a node and shortly after a message of
the same size leaves, did that node route a message or did it receive a message
and send a response? If a node receives 10 messages over the course of a few
seconds and then sends out a burst of 10 messages, it becomes even more
difficult to analyze. And a node could do that repeatedly over the course of
minutes, further blurring the lines of which messages were sent in which bursts.

These tools to thwart timing attacks can be built on. One mechanism would be to
add an urgency level to each stage of the route. When the urgency is low, nodes
can use the message as chaff, holding on to a few low urgency messages until a
high urgency message arrives, then releasing all the messages in a a randomly
ordered burst. Nodes can also strategically use routine status requests as
chaff. A node that needs to send a heartbeat message to a DHT neighbor could pad
to the same length as a message it is routing and send both out in quick
succession.

#### Stateless

But if the nodes doing the routing are the same nodes that are using the network
it cannot be assumed that their connections are persistent like a server. If a
node is currently online, it is a reasonable assumption that it will still be
online for a matter of seconds, but assumptions beyond that will not be
reliable.

For this reason, routes will be stateless. A single "Onion" encrypted message
will not work with this structure. Instead, two pieces of data will move in
parallel. One is a "Route Map" that does have an "Onion Encryption" structure.
The other is the message that may not.

### Adversarial Model

Let us assume that Alice is sending a message Bob and Bob is cooperating in
receiving the message. There are three adversarial models.

1) Alice tries to locate Bob
2) Bob tries to locate Alice
3) Eve tries to figure out if Alice and Bob are talking to each other

As in all adversarial models, the threshold is not proof, if Alice can even show
that an address is likely to belong to Bob, the security has been compromised.
The same is true for the other two cases.

In the first case, the worst case scenario is that Alice controls enough of the
network that when Bob picks nodes at random for routing, Alice controls all the
nodes. There is no defense for this. Alice can trace the message as it passes
through the network and unmask Bob.

Instead, the second to worse case scenario is defensible. Bob picks some number
of nodes and we assume that one node is honest and not controlled by Alice. In
addition, we assume that Alice can observe and inspect all network traffic, but
cannot see the internal state of honest nodes. That is the model that is assumed
for the rest of this paper.

The second and third case follow similar models.

One thing that becomes clear from looking at these models is that all data
related to routing a single message has to change completely between each hop.
The point of ciphering the message is not to make the message unreadable - the
first level of encryption does that - but to make it so that no two instances
can be correlated.

#### A Flaw in MORE

https://www.umic.rwth-aachen.de/fileadmin/user_upload/umic/results/publications/2007/landsiedel-More.pdf

A great deal of this work was inspired by the MORE paper. However it has one
flaw. The keys can be used to identify the message.

Say Alice picks N1 and N2 and Bob picks N3 and N4. But Alice is colluding with
N4. Any time Alice sees the same key that N4 sees, it becomes possible for Alice
to unmask Bob.

And this is the core cryptographic problem to this mixnet approach; given a
route like

    A → N1 → N2 → N3 → N4 → B

Where A has chosen N1 and N2 and B has chosen N3 and N4; not only should A not
know the identity of N4, but A can never see any uniquely identifiable
message data that N4 sees. And the same goes for B relative to N1. It is
necessary for A to know the identity of N3 and it is possible for B to derive
the identity of N2, that is unavoidable.

### A Classic Approach

The demo code for this appraoch can be seen at
https://github.com/dist-ribut-us/docs/tree/master/mixnetrouting/onion

It is possible to achieve this with something very similar to the MORE model.
The slight tweak is that along with the key, we include a direction; an
instruction to use the key to either encrypt or decrypt the data.

Terms:
* Route Map : A structure that describes a route. It has a "string of onions"
              structure so that it is decrypted by following the route.
* Map Packet: An individual packet in the route map. It tells a routing node
              the exchange key, the next node and the encryption direction.
* Cipher    : The cipher refers to the message with at least one layer of
              encryption.

For this example we will be looking at Alice sending a message to Bob and each
of them will choose two nodes

    A → N1 → N2 → N3 → N4 → B

All nodes publish exchange keys publicly. Bob chooses N3 and N4 at random and
uses the exchanges keys to create ephemeral keys. There has been no direct
communication between N4 and Bob, so N4 does not have a way to correlate the
ephemeral key with Bob.

Bob will construct half of the route map. Each packet is a fixed size, set by
the network. Bob will start by creating a random route ID that will be used as a
look up key. This ID is the size of one Map Packet but completely random. When
Bob later receives a message with that value in the route he will know what keys
to use to decrypt the message.

Bob then chooses N4 and creates an ephemeral exchange key. From this and N4's
public exchange key, Bob computes the ephemeral shared key. This key is used to
do a MAC'd encryption of his address and the direction (encrypting). Bob also
uses the symmetric key to do an un-MAC'd encryption of the packet he already
created (the one containing the route ID), which is appended to the end of the
route and he prepends the public ephemeral exchange key. So the message looks
like this:

    EX | Nonce | Enc(ES, Next|Add ) | EncUnMAC( R )
    EX   : ephemeral exchange key
    Nonce: Makes process non-deterministic. Same nonce is used for all 3
           cryptographic operations.
    ES   : shared key computed from ephemeral exchange key
    Next : the next node, in this case Bob
    Add  : the direction, in this case add a layer of encryption
    R    : the rest of the route 

Bob then chooses N3 and performs the same operation. Choose an ephemeral
keypair, compute the shared key, use that to encrypt the next node (N4) and
direction (Add). Use the shared key to do an un-MAC'd encrypt of the rest of the
route. Create a new route by concatenating the public ephemeral exchange key,
the new packet and the rest of the route.

Bob can do this as many times as he likes. As he's going, he must keep track of
the shared keys and when he's done, they are saved in a cache with the route ID
as the look up key.

This route is then sent to Alice (see §Full Scheme for boot strapping
communication), who does almost the same thing, but instead of the Add, she uses
the Remove instruction. It is important to note here that unlike the MORE
approach, Bob does not send any keys to Alice, only the Route Map and the first
node in the route. This means Alice has no way to collude with the last node in
the route.

Unlike Bob who needed to record the shared ephemeral keys, Alice uses them
immediately. Alice takes the message and performs a MAC'd encryption using a key
she shares with Bob. She then applies the N2 shared-key then the N1 shared-key
using un-MAC'd encryption.

Alice sends the cipher and route map to N1. N1 extracts the exchange key, nonce
and route packet. N1 computes the shared key from the exchange key. This
symmetric key is used to do a MAC'd decrypt of the packet (a fixed number of
bytes) and an un-MAC'd decrypt of the rest of the route map. The map packet
provides the location of N2 and a "Remove" instruction, which N1 follows by
removing a layer of encryption from the cipher. N1 then pads the end of the
route map with random bytes until it is the same length as when it was received.

N2 does the exact same thing and sends the resulting route and cipher to N3. N3
actually has the cipher that Bob will receive, but since it has the last layer
of encryption, this is fine. N3 performs almost the same operation except that
it will apply an un-MAC'd encrypt to the cipher. N4 will do the same thing as N3
and send the route and cipher to Bob.

Bob will receive the message as though it's just a normal routing request, but
when Bob opens it, there will be no next node, instead there will be the route
ID which Bob will use to look up the decryption keys. Bob will apply two rounds
of un-MAC'd decryption to remove the layers added by N3 and N4. Then Bob will
perform a final MAC'd decryption with the key he shares with Alice and can read
the message.

In this example Alice and Bob each chose 2 nodes, in practice they should choose
at least 3 and have the option to choose more.

#### Note on MACs

In general, un-MAC'd cryptography is not secure. It is necessary here to allow
nodes to replace portion of the route map they have consumed with random
padding. There would be no way to do that with a MAC'd encryption.

But it's important to recognize that the first layer of encryption on any piece
of data in the system is a MAC'd encryption. Which means that before any data
is actually used in any meaningful way, there is a MAC'd decrypt. Because of
this, all data does actually have MAC integrity.

#### Analysis of Classic Approach

This is a good approach. It is fast and secure. But the encrypt/decrypt
instruction reveals if the message is in the sending or receiving portion of
it's route. Better would be the same cipher was applied everywhere.

### Cyclic cipher

Another approach would be a "Cyclic Cipher". A cyclic cipher uses an arbitrarily
large set of keys. As each key is applied, it creates a new cipher text. The
cipher text is never repeated during this process. When all the keys have been
applied, the original message is recovered.

Such a cipher is possible. The next few sections will describe the cipher and
the code in this repo demonstrates it. It is presented as a proof of concept,
not a real proposal in hopes that others can build upon it to propose changes or
alternatives that reduce the overhead and increase the speed.

#### Math Foundation

This version uses the discrete log in prime fields problem as a one way function
and it built around the property

    r^(a+b) % p = r^((a+b)%(p-1)) % p

Where p is a prime and r is primitive root (also called a generator) of p. This
rule can be extended to

    r^(k1, k2, ..., kn) % p = r^((k1, k2, ..., kn)%(p-1)) % p

If we set

    k1, k2, ..., kn = p-1

then

    r^((k1, k2, ..., kn)%(p-1)) % p = 1

which means

    (M * r^k1 * r^k2 * ... * r^kn) = M

#### Choosing a Prime

The difficulty of finding primitive roots is proportional to the prime factors
of p-1. So we want to choose a prime so that this number will have very few
prime factors. This is relatively easy search. Look at the numbers that are a
product of two primes, raise them to a power high enough to make the discrete
log problem sufficiently hard then add one and check if the number is prime.

To test this theory the prime used was

    (2*571)^32 + 1

This prime may not be large enough for actual use, but it is large enough to
show the approach is somewhat practical even with large numbers.

For the chosen prime, the primitive roots are a shared table and must be public
knowledge. For simplicity, they just proceed in order, but if small values for r
is shown to be a vulnerability, it is easy to change them to a table of large
values.

#### Replay Attack

The base algorithm is completely deterministic, which makes it vulnerable to a
replay attack.

Say we have N1, N2, N3 where N2 is honest, but N1 and N3 are colluding. N1 and
N3 notice that shortly after N1 passes a message into N2, N2 passes a message to
N3. This could be the same message or it could be different. To test this, N1
creates random noise and passes it to N2 as the cipher with the same map. N1
does this twice. N3 then sees if by dividing the message

    O[1,1] = A[1,1] * r[1]^k
    O[1,2] = A[1,2] * r[2]^k
    O[2,1] = A[2,1] * r[1]^k
    O[2,2] = A[2,2] * r[2]^k

Where O is the output from N2, A is the attack and k is the key. If it was the
same message then

    O[1,1] / A[1,1] = O[2,1] / A[2,1]
    O[1,2] / A[1,2] = O[2,2] / A[2,2]

To prevent this, along with the route map and cipher, we pass along an
accumulator. Each node chooses a random value less than p-1 and adds it to both
the key and the accumulator. Since the accumulator changes randomly, it cannot
be used to perform correlation. The above becomes

    O[1,1] = A[1,1] * r[1]^(k+rnd1)
    O[1,2] = A[1,2] * r[2]^(k+rnd1)
    O[2,1] = A[2,1] * r[1]^(k+rnd2)
    O[2,2] = A[2,2] * r[2]^(k+rnd2)

and so the attack will no longer be true. Even if N1 and N3 collude and can see
the difference in the accumulator, since the accumulator is added to the key in
the exponent, they would need to solve the discrete log problem to use that
information.

To compensate for this, the receiver of the message needs to perform

    M = C * r^(p-1-acc) % p

#### Application

The demo code for this can be seen at
https://github.com/dist-ribut-us/docs/tree/master/mixnetrouting/cyclic and
https://github.com/dist-ribut-us/docs/tree/master/mixnetrouting/cyclic/cipher.
The first contains all the logic necessary for routing and the second contains
just the logic of the cipher.

Working through the same example as above

    A → N1 → N2 → N3 → N4 → B

Bob generates 3 keys, k3, k4 and kB. These are completely random.

    EX | Nonce | Enc(ES, Next) | E_unmac( R )
    EX    : ephemeral exchange key
    Nonce : Add randomness
    ES    : ephemeral shared key
    Next  : next node
    R     : rest of the route

Bob does the computation using himself as the node. For the Next value that Bob
will receive, he just inserts a special EOM message, probably all zero bytes. He
creates an ephemeral key with his own public exchange key. Only there is no
more to route yet so he does not perform an un-MAC'd encrypt.

Then he generates an ephemeral key to use with N4 and generates the shared key.
He encrypts his own location as Next with the shared key and does an un-MAC'd
encrypt on the route packets for himself.

He does the same thing for N3. Bob then computes the 3 cyclic keys. The cyclic
keys are the byte concatenation of the shared key and the nonce. The nonce
doesn't add secrecy, but it behaves as a salt. The cyclic keys are then summed
modulo p-1.

Bob sends Alice (again see §Full Scheme for boot strapping communication) the
location of N3, the route map and the key sum.

Alice chooses N2 and N1. She adds N2 and then N1 using the exact same method as
Bob. Alice then adds the cyclic keys she generated to the key sum from Bob and
generates the initial key

    k0 = p - 1 - keysum

Alice needs to prepare the message. The message needs to be broken up into
segments that are less than p. To do this, she takes the byte length of p,
subtracts one byte and breaks the message up into segments of that length and
pads each segment with a leading zero byte. Essentially breaking the message up
into numbers guaranteed to be less than p. For our example, we say the message
has 4 segments M.

Alice then computes

    C[0,0] = M[0] * r[0]^(k[0]+rnd[0]) % p
    C[0,1] = M[1] * r[1]^(k[0]+rnd[0]) % p
    C[0,2] = M[2] * r[2]^(k[0]+rnd[0]) % p
    C[0,3] = M[3] * r[3]^(k[0]+rnd[0]) % p
    Acc[0] = rnd[0]

While I will work through much of the rest of the example explicitly, the
general form of the cipher is already present here

    C[i,j] = C[i-1,j] * r[j]^(k[i]+rnd[i]) % p
    Acc[i] = Acc[i-1] + rnd[i] % (p-1)

Alice then send the route map, accumulator and cipher to N1. From the route map,
N1 uses the exchange key to compute the shared key. N1 uses the shared key and
nonce to decrypt the next node and perform an un-MAC'd decrypt on the rest of
the route map and pad the route map back to it's original length with random
bits. The shared key and the nonce are used to get the cyclic key which is used
to cycle the cipher:

    C[1,0] = C[0,0] * r[0]^(k[1]+rnd[1]) % p
    C[1,1] = C[0,1] * r[1]^(k[1]+rnd[1]) % p
    C[1,2] = C[0,2] * r[2]^(k[1]+rnd[1]) % p
    C[1,3] = C[0,3] * r[3]^(k[1]+rnd[1]) % p
    Acc[1] = Acc[1]+rnd[0] % (p-1)

Then N1 sends the route map, accumulator and cipher to N2. The same operation is
performed from N2 to N3, N3 to N4 and N4 to Bob. When Bob cycles the cipher, he
will discover that it is addressed to him. To finalize the message and correct
for the randomness introduced by each node he does

    crct := p - 1 - Acc
    M[0] = C[4,0] * r[0]^(crct) % p
    M[1] = C[4,1] * r[1]^(crct) % p
    M[2] = C[4,2] * r[2]^(crct) % p
    M[3] = C[4,3] * r[3]^(crct) % p

And then removes the zero bytes leading each message segment to recover the
original message.

#### Analysis

This cipher has some serious drawbacks. It is very slow, tuning may make it
faster but it will never be fast. There is a terrible trade off between security
and overhead. The keys should probably be 2KB-4KB each, so just 4 hops would
require 8KB-16KB of overhead, which is unacceptable.

But it shows promise. There are almost certainly better ways to accomplish the
same thing. However, my background in mathematics and cryptography is somewhat
limited and these are the only two workable solutions I have shown so far.

It does deliver the primary goal - every node performs the same cipher. It
increases the statelessness because the receiver does not need to remember any
keys.

#### Cyclic Key Strength

It may be the case that the shared key is not enough secrecy and more secret
bits will need to be included in the encrypted portion of the message, but that
is easy to implement, but increases the overhead.It would also be possible to
include the bits from the exchange key to further salt the key.

The necessary strength is difficult to compute. Unlike a normal encryption where
the objective to protect the message, the goal is to obfuscate the path taken.
In our three adversarial cases the necessary strength is influenced by how much
of the network we believe an adversary might control (in the worst case).

It is also influenced by the amount of traffic. Again, this differs from normal
encryption where an attacker chooses a cipher and tries to break it. Alice may
be colluding with N4 to unmask Bob, but she doesn't know the message will be
going through N4. The collusion will need to test the correlation on all
messages traveling through all controlled nodes shortly after Alice sends the
message. And if Bob is being cautious, he may have included requests to delay
the node, meaning that several seconds or even minutes of traffic will need to
be analyzed.

As colluding parties control more nodes, they are more likely to
have the information needed to de-anonymize the meta data, but the amount of
data that needs to be analyzed goes up drastically.

#### Indirection

An advantage this approach has over the classical approach is indirection. If
the prescribed route is

    A → N1 → N2 → N3 → N4 → B

N2 can generate additional keys whose sum is equal to it's own key and change
the route to

    A → N1 → N2 → N5 → N6 → N3 → N4 → B

This indirection can be used to mask traffic patterns. It can also be used to
route things following the natural connections of a distributed hash table
instead of needing to make one-off connections for routing. This is possible
with the previous method, but the message will remain static during indirection
which doesn't provide the additional masking.

### Additional Considerations

#### Full Scheme

How would such a system actually work in practice?

The first concept that is important is "Heisenberg Anonymity" - for any
communication one party can know either the other party's identity or their
network location but never both. Every node on the network runs an "overlay
node". Any action taken by the overlay node process is allowed to reveal the
network location - that's what it exists for. But it should never be tied to an
identity (not even a pseudonym).

The overlay nodes form a distributed hash table (DHT). The distributed hash
table allows for limited message passing. Values published to the DHT are short
(about the size of a route map) and short lived.

A simple approach is that Bob can check the DHT periodically (about once a
minute) for messages addressed to him. If Alice wants to communicate with Bob,
she posts a route map that leads back to her that is encrypted with Bob's public
key (with either an ephemeral key or a shared key if they have one established).
When Bob checks the DHT, he will see the request from Alice. Bob will respond by
creating several routes that lead back to him and sending this bundle of routes
to Alice. Alice can respond with the message she wishes to send along with a
bundle of routes. The routes will decay as nodes leave the network, but as long
as Alice and Bob are actively communicating they can keep sending new routes.

This is a simple and inefficient example. In another paper, I will discuss in
greater detail how to efficiently bridge the communication bootstrapping
problem.

#### Replay timing attacks

As noted, we can prevent the replay attack from being a simple proof, but it can
still be used as a timing attack. There is a natural balance. In order to unmask
the sender and receiver, nodes must be at opposite ends of the route, which
introduces a lot of noise. But, an attacker could re-use a route many times to
overcome this noise.

There are several ways to mitigate this, but they all break pure statelessness,
but to a degree that should be acceptable in the broader scope of the system.
Route packets will include an expiration time. This should be a matter of
seconds in the future. When a node performs a routing operation, it remembers
the key until the expiration time. If it sees the same key again, it will not
route the message. The cache should remain small because the expiration times
would only be allowed to be a few seconds or minutes in the future.

While this does break statelessness to a degree, remember that the original
argument for statelessness was that node persistence could not be relied upon.
This approach still fulfills that objective. An attacker cannot execute a replay
attack on a node that has already left the network. And upon it's return, a
node will assume a new overlay identity.

This will not provide perfect protection against timing attacks, but the only
techniques that do require a constant stream of data, which comes at a high
bandwidth cost. The network as described should allow for a good balance of
making timing attacks difficult by using routing and routine operations as
chaff.

#### Scaled Privacy

Let's not lose sight of the fact that mixnet routing exists only to protect
meta-data. A pure P2P system could be devised that does end-to-end encryption
with perfect security of the content of the messages, but it would leak who was
talking to who.

For a lot of users and a lot of network traffic, hiding this meta-data is not a
high priority and will not be worth the trade in performance. But that is fine
and can still be used to the networks advantage.

Say Alice and Bob are communicating and don't really care if Eve knows, so long
as she can't read their messages. Further, Alice and Bob are willing to break
Heisenberg Anonymity and directly share their locations with each other. Alice
can now craft a message directly to Bob, but put it in a mixnet envelope. To
the network, it will look like mixnet traffic.

But it ends up acting like a honey pot for Eve. She carefully gathers data, does
traffic and timing analysis and the data that is finally revealed only provides
information that wasn't intended to be hidden in the first place.

Further, if Alice and Bob are communicating openly they can publish this
information as a "Garlic Bridge". Other users who need the protection of the
mixnet can include low-urgency hops between Alice and Bob. These messages can be
cached until Alice is sending a message to Bob (or vice-versa) and then piggy-
back on the message.

This flexibility allows for users who value performance and users who value the
anonymity of their meta-data (and the protection of all message data). Users can
even adjust their protection on a context basis. Alice can communicate openly
with Bob but keep her communication with Carol protected.

#### Freeloading

Nodes have little incentive to freeload. Because all network traffic is wrapped
in mixnet envelopes, a node has to perform the first half of the routing
protocol to receive any messages.

A node could potentially decline to route at this point, but it would be easy to
identify these nodes. Just send messages through the suspect node and see if
they are delivered. Once nodes are detected, they can be black listed and
traffic to and from them will be blocked.

#### Packet Size

This is not a topic I've delved into in any depth, but is worth mentioning. If
packets are of arbitrary size, that makes them identifiable, negating the whole
point. The two approaches worth considering are to either break all messages up
into packets of a fixed size (padding where necessary) or have available sizes
that double (4k, 8k 16k, 32k, 64k).

The second option provides more flexibility. It would be possible to group
several messages together so that when a routing node receives them, they will
break apart into smaller messages.

### Conclusion

A P2P, stateless, serverless mixnet routing protocol where all nodes on the
network are potential routers allows for a network that can scale with its use
and provide meta-data protection against most adversaries while offering a
reasonably performant option to users who need less protection. This paper
described two methods for routing messages. The first is only a slight variation
on traditional onion routing techniques, most closely inspired by the MORE
paper. The second was an original approach that could allow more flexibility,
but in it's current form is too slow and requires too much overhead. A few of
the more important issues related to the operation of such a network are
considered, though many issues remain that need consideration.

This paper is intended to be the first of several outlining a proposal for such
a network. Feedback is welcome.