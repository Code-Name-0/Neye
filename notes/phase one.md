#camel
this is where packets are captured from the network, hosted in the [[laptop]]

this phase's responsibility is only to capture traffic going through the network, filtering by the source to only capture traffic from the switch/raspberries, and place packets inside a queue.
# Functionalities 
- filter incoming traffic by source.
- structure captured packets in the desired structure.
- access to a queue, adding packets to it.




[[Stations#Station 1|Station 1]]
the structure of IPv4 packet
![[Pasted image 20250420104846.png]]

**what fields should I keep?**

lets filter things I do not need, while keeping tracks of the index (in bits):

```python
filtered_index = []
```

- version: always 4 for IPv4 
```python
filtered_index = [(0,3)]
```


**for now, only the version will be removed, but later when the list of features is fixed, header parts not contributing to the features extraction phase will be also removed.**


now to the technical part

[[Stations#Station 2|Station 2]]

C, C++ or python?

since the system is meant for real-time work and needs high performance, and the aim to use multi-threading approach,  C/C++ is preferable.

high complexity and more work needed while developing, okay...

C or C++?

C++ because of OOP support, standard libraries, safer memory management

**Do I know C++? No...**

**this might be an obstacle that will slow down the process, keep tracking your time!**


## Design

initial design:




pseudo code:

```
function capture(){
	
}
```
