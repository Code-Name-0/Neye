#camel


this is the main process that executes all the other phases

# responsibilities:
- group devices [[Main Process#Grouping devices|here]]
- launch threads [[Main Process#Threads|here]]


## Grouping devices

devices will be grouped into **$K$** groups, fragmenting will be as follows:

using their IP addresses to determine their group index: 
```python
group_idx = int( ''.join(IP_addr.split('.')[(ip_mask // 8) : ]) ) % K
```
**the problem here is that the nature of the traffic is not taken into consideration, this can lead to one device sending a lot of traffic which can overload the queue, leading to loss pf packets or delays.**


<mark style="background: #FFF3A3A6;">it will be better and safer to group devices by their traffic type: high-bandwidth vs low-bandwidth to assure proper load balancing. </mark>


the grouping process will be manual for now, until further analysis.

as for the code, maybe using a json or a local mapping for device-group, but using IP addresses might pose a problem as they can change over time, so maybe MAC addresses? or will the network configuration be static?

I might go for the approach with MAC addresses because it does not add a lot of overhead, the main process reads the map, gets the list of connected devices,get their mac addresses to assign them groups and their IP address, pass it to the thread responsible for packet capture. This process is done only once when the system is turned on.


<mark style="background: #FFF3A3A6;">a good addition would be a way to handle new devices that are not in the label map

use first index method to determine the group, and raise an alert to the admins to let them know about the new device and that it might be better to manually analyse its traffic and appropriate group.</mark>


## Threads








## Pseudo Code

```
- Read devices-group map json using nlohmann_json.
- Query /proc/net/arp for MAC-to-IP mappings.
- Group devices by "group" field (e.g., 0 to 3 for K=4).
- Generate filters like "src host 192.168.1.100 or src host 192.168.1.101".
```

