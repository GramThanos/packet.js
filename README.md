# packet.js
A packet analyser in JavaScript

This is currently in demo phase and needs testing.

___

### Features

Supported protocols:
- Ethernet II
- IPv4
- IPv6
- ARP
- UDP
- TCP

___

### Usage
```javascript
// Load library
const Packet = require('./packet');

// Set logging to debug
Packet.Log.level = Packet.Log.Levels.DEBUG;

// List of packets in hex format
let packets = [
    'ffffffffffff6adfc05823cc080600010800060400016adfc05823cc0a0500010000000000000a05fc71',
];
// Parse packets from hex to Uint8Array
packets = packets.map(packet => Packet.Utils.fromHexString(packet));

// Analyse each packet
packets = packets.map(packet => new Packet.EthernetII(packet));

// For each packet print protocols encapsulated
packets.forEach(packet => {
	console.log(packet.stack().join('>'));
});
```

___

### License

This project is under [The MIT license](https://opensource.org/licenses/MIT).
I do although appreciate attribute.

Copyright (c) 2023 Grammatopoulos Athanasios-Vasileios

