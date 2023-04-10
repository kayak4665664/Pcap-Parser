# Pcap-Parser

It's used to parse the pcap file, and extract the data of each layer from the data link layer, network layer, transport layer, and then to the application layer. The application layer supports `HTTP` and `TLS` protocols.
用于解析pcap文件，从数据链路层、网络层、传输层、再到应用层，提取出各层的数据。应用层支持`HTTP`和`TLS`协议。

An executable file can be built using the following command，可以使用如下指令生成可执行文件：

```shell
g++ -O3 -g pcap_parser.cpp -std=c++2a -o pcap_parser -lpcap
```

Then you can use the following command to run the program, and the result will be output to the `text` file，之后可以使用如下指令运行程序，结果会输出到`text`文件中：
```shell
./pcap_parser <pcap file>
```

The following is an example of parsed results，以下是一个解析结果的示例：

```
Packet number: 1
Packet length: 110
Bytes captured: 110
Received time: Mon Apr  3 16:08:37 2023
+++++++++++++++++++++++++++++++++++++++++++++
Destination MAC address: 42:01:0a:b6:00:02
Source MAC address: 42:01:0a:b6:00:01
Ethernet type: 0x0800 (IPv4)
+++++++++++++++++++++++++++++++++++++++++++++
IP Version: 4
IP Header length: 20 bytes (5)
Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)
Total length: 96
Identification: 0xd782 (55170)
Fragment offset field: 0x4000
Flags: 0x2, Don't fragment
Fragment offset: 0
Time to live: 54
Protocol: TCP (6)
Header checksum: 0xcd59
Source IP address: 
Destination IP address: 
+++++++++++++++++++++++++++++++++++++++++++++
TCP Source port: 49786
TCP Destination port: 46133
Sequence number: 826271802
Acknowledgement number: 2309518908
Header length: 32 bytes (8)
Flags: 0x018 Push Acknowlegment
Window: 174
Checksum: 0x250e
Urgent pointer: 0
TCP Option - No-Operation (NOP)
TCP Option - No-Operation (NOP)
TCP Option - Timestamps (TS)
Length: 10
TS Value: 14503087
TS Echo Reply: 2336553410
```