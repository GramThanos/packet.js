/*
 * packet.js v0.0.1-beta
 * Author: Athanasios Vasileios Grammatopoulos
 * MIT License
 */

(function (exports) {
	"use strict";

	// Helpfull Untilities
	const Utils = {
		fromHexString : (str) => {
			return Uint8Array.from(str.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
		},
		toHexString : (bytes) => {
			return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
		},

		toMAC : (bytes) => {
			if (bytes.byteLength == 6)
				return [... bytes].map((byte) => byte.toString(16).padStart(2, '0')).join(':');
			return false;
		},
		toIPv4 : (bytes) => {
			if (bytes.byteLength == 4)
				return [... bytes].map((byte) => byte.toString(10)).join('.');
			return false;
		},
		toIPv6 : (bytes) => {
			if (bytes.byteLength == 16)
				return Array.from({length: bytes.byteLength / 2}, (_, i) => bytes[2 * i].toString(16).padStart(2, '0') + bytes[2 * i + 1].toString(16).padStart(2, '0')).join(':');
			return false;
		}
	};

	const Log = {
		Levels : {
			TRACE : 1,
			DEBUG : 2,
			INFO  : 3,
			WARN  : 4,
			ERROR : 5,
			FATAL : 6,
			NONE  : 7
		},
		print : function(level) {
			if (level >= this.level)
				console.log('[Packet.js]', ... [... arguments].splice(1));
		},

		trace : function() {this.print(this.Levels.TRACE, ...arguments);},
		debug : function() {this.print(this.Levels.DEBUG, ...arguments);},
		info  : function() {this.print(this.Levels.INFO , ...arguments);},
		warn  : function() {this.print(this.Levels.WARN , ...arguments);},
		error : function() {this.print(this.Levels.ERROR, ...arguments);},
		fatal : function() {this.print(this.Levels.FATAL, ...arguments);},
	};
	Log.level = Log.Levels.FATAL;


	function EthernetII(data) {
		if (!data) return;
		if (data instanceof Uint8Array) {
			this.from(data);
		}
	}
	EthernetII.prototype.from = function(bytes) {
		this.raw = bytes;
		this.dst = bytes.subarray(0, 6);
		this.src = bytes.subarray(6, 12);

		// https://en.wikipedia.org/wiki/EtherType
		this.type = (bytes[12] << 8) + bytes[13]; //bytes.subarray(12, 14);

		let payload = bytes.subarray(14, bytes.byteLength);
		if (this.type > 1500) {
			// TODO: Check. Payload must be of max 9000 bytes

			if (this.type == 0x0800) {
				this.payload = new IPv4(payload);
			}
			else if (this.type == 0x0806) {
				this.payload = new ARP(payload);
			}
			else if (this.type == 0x86DD) {
				this.payload = new IPv6(payload);
			}
			else {
				Log.warn(`Unsupported EthernetII Type ${this.type}.`);
				this.payload = new Raw(payload);
			}
		}
		else {
			this.payload = new Raw(payload);
		}

		return this;
	};
	EthernetII.prototype.stack = function() {
		return ['EthernetII', ... (this.payload && this.payload.stack ? this.payload.stack() : [])];
	};

	// https://en.wikipedia.org/wiki/Internet_Protocol_version_4
	function IPv4(data) {
		if (!data) return;
		if (data instanceof Uint8Array) {
			this.from(data);
		}
	}
	IPv4.prototype.from = function(bytes) {
		this.raw = bytes;
		this.version = bytes[0] >> 4;
		this.ihl = bytes[0] & 0xf;
		this.dscp = bytes[1] >> 2;
		this.ecn = bytes[1] & 0x3;
		this.length = (bytes[2] << 8) + bytes[3];
		this.identification = (bytes[4] << 8) + bytes[5];
		this.flags = bytes[6] >> 5;
		this.fragment_offset = ((bytes[6] & 0x1f) << 8) + bytes[7];
		this.ttl = bytes[8];
		this.protocol = bytes[9];
		this.header_checksum = bytes.subarray(10, 12);
		this.src = bytes.subarray(12, 16);
		this.dst = bytes.subarray(16, 20);
		this.options = this.ihl > 5 ? bytes.subarray(20, 20 + (this.ihl - 5) * 4) : new Uint8Array();

		if (this.version != 4) {
			Log.warn(`Invalid version on IPv4 packet.`);
		}

		let payload = bytes.subarray(20 + (this.ihl - 5) * 4, bytes.byteLength);
		// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
		if (this.protocol == 6) {
			this.payload = new TCP(payload);
		}
		else if (this.protocol == 17) {
			this.payload = new UDP(payload);
		}
		else {
			Log.warn(`Unsupported IP Protocol ${this.protocol}.`);
			this.payload = new Raw(payload);
		}
		return this;
	};
	IPv4.prototype.stack = function() {
		return ['IPv4', ... (this.payload && this.payload.stack ? this.payload.stack() : [])];
	};

	// https://en.wikipedia.org/wiki/Address_Resolution_Protocol
	function ARP(data) {
		if (!data) return;
		if (data instanceof Uint8Array) {
			this.from(data);
		}
	}
	ARP.prototype.from = function(bytes) {
		this.raw = bytes;

		this.htype = (bytes[0] << 8) + bytes[1]; // Hardware type
		this.ptype = (bytes[2] << 8) + bytes[3]; // Protocol type
		this.hlen = bytes[4]; // Hardware length
		this.plen = bytes[5]; // Protocol length
		this.operation = (bytes[6] << 8) + bytes[7];

		this.sha = bytes.subarray(8, 14); // Sender hardware address (SHA)
		this.spa = bytes.subarray(14, 18); // Sender protocol address (SPA)
		this.tha = bytes.subarray(18, 24); // Target hardware address (THA)
		this.tpa = bytes.subarray(24, 28); // Target protocol address (TPA)

		if (bytes.byteLength < 28) {
			Log.error(`Missing ${28 - bytes.byteLength} bytes from ARP packet.`);
		}
		else if (bytes.byteLength > 28) {
			Log.warn(`Extra ${bytes.byteLength - 28} bytes on ARP packet.`);
		}

		return this;
	};
	ARP.prototype.stack = function() {
		return ['ARP'];
	};

	// https://en.wikipedia.org/wiki/IPv6_packet
	function IPv6(data) {
		if (!data) return;
		if (data instanceof Uint8Array) {
			this.from(data);
		}
	}
	IPv6.prototype.from = function(bytes) {
		this.raw = bytes;

		this.version = bytes[0] >> 4;

		this.traffic_class = ((bytes[0] & 0xf) << 8) + (bytes[1] >> 4);
		this.ds_field = (this.traffic_class >> 2);
		this.ecn = (this.traffic_class & 0x3);
		this.flow_label = ((bytes[1] & 0xf) << 16) + (bytes[2] << 8) + bytes[3];
		this.payload_length = (bytes[4] << 8) + bytes[5];
		this.next_header = bytes[6];
		this.hop_limit = bytes[7];
		this.src = bytes.subarray(8, 24);
		this.dst = bytes.subarray(24, 40);

		// Checks
		if (this.version != 6) {
			Log.warn(`Invalid version on IPv6 packet.`);
		}
		let payload_bytes_length = bytes.byteLength - 40;
		if (this.payload_length > payload_bytes_length) {
			Log.error(`Missing ${this.length - payload_bytes_length} bytes from IPv6 packet.`);
		}
		else if (this.payload_length < bytes.byteLength - 40) {
			Log.warn(`Extra ${payload_bytes_length - this.length} bytes on IPv6 packet.`);
		}

		let payload = bytes.subarray(40, 40 + this.payload_length);
		// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
		if (this.next_header == 6) {
			this.payload = new TCP(payload);
		}
		else if (this.next_header == 17) {
			this.payload = new UDP(payload);
		}
		else {
			Log.warn(`Unsupported IP Protocol ${this.next_header}.`);
			this.payload = new Raw(payload);
		}
		return this;
	};
	IPv6.prototype.stack = function() {
		return ['IPv6', ... (this.payload && this.payload.stack ? this.payload.stack() : [])];
	};

	// https://en.wikipedia.org/wiki/User_Datagram_Protocol
	function UDP(data) {
		if (!data) return;
		if (data instanceof Uint8Array) {
			this.from(data);
		}
	}
	UDP.prototype.from = function(bytes) {
		this.raw = bytes;
		this.sport = (bytes[0] << 8) + bytes[1];
		this.dport = (bytes[2] << 8) + bytes[3];
		this.length = (bytes[4] << 8) + bytes[5];
		this.checksum = bytes.subarray(5, 7);

		// Checks
		if (this.length > bytes.byteLength) {
			Log.error(`Missing ${this.length - bytes.byteLength} bytes from UDP packet.`);
		}
		else if (this.length < bytes.byteLength) {
			Log.warn(`Extra ${bytes.byteLength - this.length} bytes on UDP packet.`);
		}

		let payload = bytes.subarray(7, this.length);
		this.data = payload;

		return this;
	};
	UDP.prototype.stack = function() {
		return ['UDP', ... (this.payload && this.payload.stack ? this.payload.stack() : [])];
	};

	// https://en.wikipedia.org/wiki/Transmission_Control_Protocol
	function TCP(data) {
		if (!data) return;
		if (data instanceof Uint8Array) {
			this.from(data);
		}
	}
	TCP.prototype.from = function(bytes) {
		this.raw = bytes;
		this.sport = (bytes[0] << 8) + bytes[1];
		this.dport = (bytes[2] << 8) + bytes[3];
		this.sequence_number = (bytes[4] << 24) + (bytes[5] << 16) + (bytes[6] << 8) + bytes[7];
		this.acknowledgmen_number = (bytes[8] << 24) + (bytes[9] << 16) + (bytes[10] << 8) + bytes[11];
		this.data_offset = bytes[12] >> 4;
		this.reserved = (bytes[12] & 0xf) >> 1;
		
		this.flag_ns = (bytes[12] & 0x1) > 0;
		this.flag_cwr = (bytes[13] & 0x128) > 0;
		this.flag_ece = (bytes[13] & 0x64) > 0;
		this.flag_urg = (bytes[13] & 0x32) > 0;
		this.flag_ack = (bytes[13] & 0x16) > 0;
		this.flag_psh = (bytes[13] & 0x8) > 0;
		this.flag_rst = (bytes[13] & 0x4) > 0;
		this.flag_syn = (bytes[13] & 0x2) > 0;
		this.flag_fin = (bytes[13] & 0x1) > 0;

		this.window_size = (bytes[14] << 8) + bytes[15];
		this.checksum = bytes.subarray(15, 17);
		this.urgent_pointer = bytes.subarray(17, 19);

		this.options = this.data_offset > 5 ? bytes.subarray(19, 19 + (this.data_offset - 5) * 4) : new Uint8Array();

		let payload = bytes.subarray(19 + (this.data_offset - 5) * 4, bytes.byteLength);
		this.data = payload;

		return this;
	};
	TCP.prototype.stack = function() {
		return ['TCP', ... (this.payload && this.payload.stack ? this.payload.stack() : [])];
	};

	// Raw Payload
	function Raw(data) {
		if (!data) return;
		if (data instanceof Uint8Array) {
			this.from(data);
		}
	}
	Raw.prototype.from = function(bytes) {
		this.raw = bytes;
		return this;
	};
	Raw.prototype.stack = function() {
		return ['RAW'];
	};

	// Export protocols
	exports.EthernetII = EthernetII;
	exports.IPv4 = IPv4;
	exports.ARP = ARP;
	exports.IPv6 = IPv6;
	exports.UDP = UDP;
	exports.TCP = TCP;

	// Export helping functions
	exports.version = 'v0.0.1-beta';
	exports.Utils = Utils;
	exports.Log = Log;

})(typeof exports === 'undefined' ? this['Packet'] = {} : exports);
