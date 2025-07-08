#khabir
moving toward: [[destination]]



First things first, the environment setup, starting with an experimental environment using raspberry pi devices and my laptop to simulate real situations

- **raspi_1**: acts like the medical equipment, simply receiving packets and responding with a simple HTTP response. [[raspi_1|details]]
- **raspi_2**: benign user, to simulate normal request to the IoMT system, like the doctors' using the platform. [[raspi_2|details]]
- **raspi_3**: acts like a threat actor, to simulate some attacks. [[raspi_3|details]]
- **laptop**: two responsibilities: [[laptop|details]]
	1. A proxy responsible for routing all packets between all raspi devices.
	2. hosting the sniffing system to intercepting all packets between the raspi devices and inference using the IDS model.


the three raspi devices are configured to automatically connect to phone's hotspot on boot up and start an ssh server. I can access them using any ssh client software, including vs code with the right plugin, allowing me to directly write and test my code on them.

<mark style="background: #FFF3A3A6;">to connect to raspi_x: ssh raspi_*x*@raspi*x*.local, password: raspi_*x* where x is 1, 2 or 3</mark>


# Phase 1
**capture traffic**, this phase consists of only capturing the traffic going through the network, it starts when a packet arrives into the laptop, in a real situation the packets are redirected from the switch (port mirroring), in the experimental setup, it will be sourced from the raspi devices with the destination being the proxy in the laptop. [[phase one|details]]

**input**: raw network traffic
**output**: structured packets 

# Phase 2

**feature extraction**, in this phase, needed features are calculated based on data extracted from the captured traffic, hosted in the laptop.  [[phase two|details]]

**input**: structured packets
**output**: calculated features
# Phase 3

IDS inference, this is the simplest phase, it only consist of using the already trained ai model to evaluate the flow and predict its class, in the case of labeling the flow as any of the attacks, a signal should be sent to administrators. [[phase three|details]]

**input**: calculated features
**output**: IDS prediction



## System Design

the sniffer will run in multi-threaded environment

one [[Main Process]], launching K thread responsible for [[Conception#Phase 1|phase 1]], each thread launches another thread responsible for [[Conception#Phase 2|phase 2]].







## Option 1
this method involve <mark style="background: #FFF3A3A6;">two I/O operations</mark> which can slow down the process

## Option 2





phases one and three are straight forward, the question is about phase two

<mark style="background: #FF5582A6;">how will features be extracted? </mark>

### option 1:
- by saving captures traffic into pcap and extracting features from it

### option 2:
- by doing everything in ram, directly extract features from the captured packets as they arrive in real-time
