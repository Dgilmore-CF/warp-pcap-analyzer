/**
 * Deep PCAP/PCAPNG Decoder
 * Full protocol analysis with Wireshark-quality packet inspection.
 * Supports Ethernet, IPv4/v6, TCP, UDP, ICMP, ARP, DNS, TLS, HTTP, DHCP.
 * Tracks TCP streams and conversation flows for the UI.
 */

// ── Constants ──────────────────────────────────────────────────────────────────

const ETHER_TYPES = {
	0x0800: 'IPv4',
	0x0806: 'ARP',
	0x86dd: 'IPv6',
	0x8100: '802.1Q',
	0x88a8: '802.1ad',
};

const IP_PROTOCOLS = {
	1: 'ICMP', 6: 'TCP', 17: 'UDP', 41: 'IPv6-in-IPv4',
	47: 'GRE', 50: 'ESP', 51: 'AH', 58: 'ICMPv6',
	89: 'OSPF', 132: 'SCTP',
};

const TCP_FLAGS = {
	0x01: 'FIN', 0x02: 'SYN', 0x04: 'RST', 0x08: 'PSH',
	0x10: 'ACK', 0x20: 'URG', 0x40: 'ECE', 0x80: 'CWR',
};

const ICMP_TYPES = {
	0: 'Echo Reply', 3: 'Destination Unreachable', 4: 'Source Quench',
	5: 'Redirect', 8: 'Echo Request', 9: 'Router Advertisement',
	10: 'Router Solicitation', 11: 'Time Exceeded',
	12: 'Parameter Problem', 13: 'Timestamp Request',
	14: 'Timestamp Reply', 17: 'Address Mask Request',
	18: 'Address Mask Reply',
};

const ICMP_DEST_UNREACHABLE_CODES = {
	0: 'Net Unreachable', 1: 'Host Unreachable', 2: 'Protocol Unreachable',
	3: 'Port Unreachable', 4: 'Fragmentation Needed', 5: 'Source Route Failed',
	6: 'Destination Network Unknown', 7: 'Destination Host Unknown',
	13: 'Communication Administratively Prohibited',
};

const DNS_TYPES = {
	1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR',
	15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 35: 'NAPTR',
	41: 'OPT', 43: 'DS', 46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY',
	65: 'HTTPS', 99: 'SPF', 252: 'AXFR', 255: 'ANY', 257: 'CAA',
};

const DNS_CLASSES = { 1: 'IN', 3: 'CH', 4: 'HS', 255: 'ANY' };

const DNS_RCODES = {
	0: 'No Error', 1: 'Format Error', 2: 'Server Failure',
	3: 'Name Error (NXDOMAIN)', 4: 'Not Implemented', 5: 'Refused',
};

const TLS_CONTENT_TYPES = {
	20: 'ChangeCipherSpec', 21: 'Alert', 22: 'Handshake', 23: 'ApplicationData',
};

const TLS_HANDSHAKE_TYPES = {
	0: 'HelloRequest', 1: 'ClientHello', 2: 'ServerHello',
	4: 'NewSessionTicket', 11: 'Certificate', 12: 'ServerKeyExchange',
	13: 'CertificateRequest', 14: 'ServerHelloDone',
	15: 'CertificateVerify', 16: 'ClientKeyExchange', 20: 'Finished',
};

const TLS_VERSIONS = {
	0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1',
	0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3',
};

const WELL_KNOWN_PORTS = {
	20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
	53: 'DNS', 67: 'DHCP-Server', 68: 'DHCP-Client', 69: 'TFTP',
	80: 'HTTP', 110: 'POP3', 123: 'NTP', 143: 'IMAP', 161: 'SNMP',
	162: 'SNMP-Trap', 443: 'HTTPS', 465: 'SMTPS', 500: 'IKE',
	514: 'Syslog', 587: 'SMTP-Submit', 853: 'DNS-over-TLS',
	993: 'IMAPS', 995: 'POP3S', 1194: 'OpenVPN', 1723: 'PPTP',
	2408: 'Cloudflare-WARP', 3389: 'RDP', 4500: 'IPsec-NAT-T',
	5060: 'SIP', 5061: 'SIPS', 5222: 'XMPP', 5223: 'XMPP-TLS',
	8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 8853: 'DNS-over-HTTPS',
};

const DHCP_MESSAGE_TYPES = {
	1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline',
	5: 'ACK', 6: 'NAK', 7: 'Release', 8: 'Inform',
};

// File size thresholds — tuned for 128MB Worker memory + 30s CPU
const LARGE_FILE_THRESHOLD = 5 * 1024 * 1024;  // 5MB
const MAX_PACKETS_DEFAULT = 2000;               // Reduced from 10K — each decoded packet is ~2-5KB in memory
const MAX_PACKETS_LARGE = 5000;                 // Reduced from 50K — prevents OOM on large captures

// ── Main decoder ───────────────────────────────────────────────────────────────

/**
 * Decode an entire PCAP or PCAPNG file into structured packet data.
 * @param {Uint8Array} data  Raw file bytes
 * @param {Object}     opts  { maxPackets?: number }
 * @returns {{ metadata, packets, flows, stats, warnings }}
 */
export function decodePcapFile(data, opts = {}) {
	const warnings = [];
	const isLarge = data.length > LARGE_FILE_THRESHOLD;
	const maxPackets = opts.maxPackets || (isLarge ? MAX_PACKETS_LARGE : MAX_PACKETS_DEFAULT);

	if (isLarge) {
		warnings.push({
			type: 'large_file',
			message: `Large file detected (${formatBytes(data.length)}). Analysis limited to ${maxPackets.toLocaleString()} packets. Some features may have reduced fidelity.`,
		});
	}

	if (data.length < 12) {
		return { metadata: { error: 'File too small to be a valid capture' }, packets: [], flows: {}, stats: {}, warnings };
	}

	const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
	const magic = view.getUint32(0, true);
	const isPcapNg = magic === 0x0a0d0d0a;
	const isPcap = magic === 0xa1b2c3d4 || magic === 0xd4c3b2a1;

	if (!isPcap && !isPcapNg) {
		return { metadata: { error: 'Unrecognised capture format (invalid magic number)' }, packets: [], flows: {}, stats: {}, warnings };
	}

	let result;
	if (isPcapNg) {
		result = decodePcapNg(data, view, maxPackets, warnings);
	} else {
		result = decodePcapLegacy(data, view, maxPackets, warnings);
	}

	// Build flows and statistics from decoded packets
	const flows = buildFlows(result.packets);
	const stats = buildStatistics(result.packets, flows, result.metadata);

	return { metadata: result.metadata, packets: result.packets, flows, stats, warnings };
}

// ── PCAP Legacy format ─────────────────────────────────────────────────────────

function decodePcapLegacy(data, view, maxPackets, warnings) {
	const magic = view.getUint32(0, true);
	const isLE = magic === 0xa1b2c3d4;

	const metadata = {
		format: 'PCAP',
		version: `${view.getUint16(4, isLE)}.${view.getUint16(6, isLE)}`,
		snaplen: view.getUint32(16, isLE),
		linkType: view.getUint32(20, isLE),
		fileSize: data.length,
		totalPackets: 0,
	};

	const packets = [];
	let offset = 24;
	let num = 0;

	while (offset + 16 <= data.length && num < maxPackets) {
		const tsSec = view.getUint32(offset, isLE);
		const tsUsec = view.getUint32(offset + 4, isLE);
		const capLen = view.getUint32(offset + 8, isLE);
		const origLen = view.getUint32(offset + 12, isLE);

		if (capLen > 262144 || offset + 16 + capLen > data.length) {
			warnings.push({ type: 'truncated', message: `Packet ${num + 1}: truncated or corrupt at offset ${offset}` });
			break;
		}

		const timestamp = tsSec + tsUsec / 1_000_000;
		const rawBytes = data.slice(offset + 16, offset + 16 + capLen);

		const packet = decodePacket(num, timestamp, rawBytes, capLen, origLen, metadata.linkType, view, offset + 16);
		packets.push(packet);
		num++;
		offset += 16 + capLen;
	}

	// Count remaining packets without decoding
	while (offset + 16 <= data.length) {
		const capLen = view.getUint32(offset + 8, isLE);
		if (capLen > 262144 || offset + 16 + capLen > data.length) break;
		num++;
		offset += 16 + capLen;
	}

	metadata.totalPackets = num;
	if (num > packets.length) {
		warnings.push({
			type: 'limit',
			message: `Showing ${packets.length.toLocaleString()} of ${num.toLocaleString()} total packets`,
		});
	}

	return { metadata, packets };
}

// ── PCAPNG format ──────────────────────────────────────────────────────────────

function decodePcapNg(data, view, maxPackets, warnings) {
	const metadata = {
		format: 'PCAPNG',
		version: 'NG',
		snaplen: 65535,
		linkType: 1,
		fileSize: data.length,
		totalPackets: 0,
		interfaces: [],
	};

	const packets = [];
	let offset = 0;
	let num = 0;
	let decoded = 0;

	while (offset + 8 <= data.length) {
		const blockType = view.getUint32(offset, true);
		const blockLen = view.getUint32(offset + 4, true);

		if (blockLen < 12 || offset + blockLen > data.length) break;

		switch (blockType) {
			case 0x0a0d0d0a: // Section Header Block
				break;

			case 0x00000001: { // Interface Description Block
				if (blockLen >= 20) {
					const lt = view.getUint16(offset + 8, true);
					const snap = view.getUint32(offset + 12, true);
					metadata.interfaces.push({ linkType: lt, snaplen: snap });
					if (metadata.interfaces.length === 1) {
						metadata.linkType = lt;
						metadata.snaplen = snap;
					}
				}
				break;
			}

			case 0x00000006: { // Enhanced Packet Block
				if (blockLen >= 32 && decoded < maxPackets) {
					const ifId = view.getUint32(offset + 8, true);
					const tsHigh = view.getUint32(offset + 12, true);
					const tsLow = view.getUint32(offset + 16, true);
					const capLen = view.getUint32(offset + 20, true);
					const origLen = view.getUint32(offset + 24, true);

					if (capLen <= blockLen - 32 && offset + 28 + capLen <= data.length) {
						// Timestamp in microseconds (default resolution)
						const timestamp = (tsHigh * 4294967296 + tsLow) / 1_000_000;
						const rawBytes = data.slice(offset + 28, offset + 28 + capLen);
						const linkType = metadata.interfaces[ifId]?.linkType || metadata.linkType;

						const packet = decodePacket(decoded, timestamp, rawBytes, capLen, origLen, linkType, view, offset + 28);
						packets.push(packet);
						decoded++;
					}
				}
				num++;
				break;
			}

			case 0x00000003: // Simple Packet Block
			case 0x00000002: // Obsolete Packet Block
				num++;
				if (decoded < maxPackets) {
					// Minimal decode for simple/obsolete blocks
					const capLen2 = view.getUint32(offset + 8, true);
					if (capLen2 <= blockLen - 16 && offset + 12 + capLen2 <= data.length) {
						const rawBytes = data.slice(offset + 12, offset + 12 + capLen2);
						const packet = decodePacket(decoded, 0, rawBytes, capLen2, capLen2, metadata.linkType, view, offset + 12);
						packets.push(packet);
						decoded++;
					}
				}
				break;
		}

		offset += blockLen;
	}

	metadata.totalPackets = num;
	if (num > packets.length) {
		warnings.push({
			type: 'limit',
			message: `Showing ${packets.length.toLocaleString()} of ${num.toLocaleString()} total packets`,
		});
	}

	return { metadata, packets };
}

// ── Packet decode ──────────────────────────────────────────────────────────────

function decodePacket(num, timestamp, rawBytes, capLen, origLen, linkType, view, dataOffset) {
	const pkt = {
		number: num + 1,
		timestamp,
		capturedLength: capLen,
		originalLength: origLen,
		layers: {},
		protocol: 'Unknown',
		info: '',
		flowId: '',
		// rawHex is generated lazily by the UI from rawBytes to save memory
		rawBytes: Array.from(rawBytes),
		warnings: [],
	};

	if (capLen !== origLen) {
		pkt.warnings.push(`Truncated: captured ${capLen} of ${origLen} bytes`);
	}

	try {
		// Frame layer
		pkt.layers.frame = {
			number: pkt.number,
			length: origLen,
			capturedLength: capLen,
			timestamp: pkt.timestamp,
			protocols: '',
		};

		if (linkType === 1 && capLen >= 14) {
			// Ethernet II
			decodeEthernet(rawBytes, 0, pkt);
		} else if (linkType === 101 && capLen >= 20) {
			// Raw IP (no Ethernet header)
			const version = (rawBytes[0] >> 4) & 0x0f;
			if (version === 4) {
				decodeIPv4(rawBytes, 0, pkt);
			} else if (version === 6) {
				decodeIPv6(rawBytes, 0, pkt);
			}
		} else {
			pkt.protocol = `LinkType-${linkType}`;
			pkt.info = `Unknown link type ${linkType}, ${capLen} bytes`;
		}

		// Build protocol chain
		const layerNames = Object.keys(pkt.layers).filter(l => l !== 'frame');
		pkt.layers.frame.protocols = layerNames.join(':');

	} catch (e) {
		pkt.warnings.push(`Decode error: ${e.message}`);
		if (!pkt.protocol || pkt.protocol === 'Unknown') {
			pkt.protocol = 'Malformed';
			pkt.info = `Decode error at byte offset (${e.message})`;
		}
	}

	return pkt;
}

// ── Layer 2: Ethernet ──────────────────────────────────────────────────────────

function decodeEthernet(data, offset, pkt) {
	if (offset + 14 > data.length) return;

	const dstMac = formatMac(data, offset);
	const srcMac = formatMac(data, offset + 6);
	let etherType = (data[offset + 12] << 8) | data[offset + 13];
	let nextOffset = offset + 14;

	// Handle 802.1Q VLAN tagging
	let vlanId = null;
	if (etherType === 0x8100) {
		if (nextOffset + 4 > data.length) return;
		vlanId = ((data[nextOffset] & 0x0f) << 8) | data[nextOffset + 1];
		etherType = (data[nextOffset + 2] << 8) | data[nextOffset + 3];
		nextOffset += 4;
	}

	pkt.layers.ethernet = {
		dst: dstMac,
		src: srcMac,
		type: etherType,
		typeName: ETHER_TYPES[etherType] || `0x${etherType.toString(16).padStart(4, '0')}`,
		vlanId,
	};

	pkt.protocol = pkt.layers.ethernet.typeName;
	pkt.info = `${srcMac} → ${dstMac}`;

	// Dispatch to L3
	switch (etherType) {
		case 0x0800: decodeIPv4(data, nextOffset, pkt); break;
		case 0x86dd: decodeIPv6(data, nextOffset, pkt); break;
		case 0x0806: decodeARP(data, nextOffset, pkt); break;
		default:
			pkt.info += ` | EtherType 0x${etherType.toString(16).padStart(4, '0')}`;
	}
}

// ── Layer 3: IPv4 ──────────────────────────────────────────────────────────────

function decodeIPv4(data, offset, pkt) {
	if (offset + 20 > data.length) return;

	const versionIHL = data[offset];
	const ihl = (versionIHL & 0x0f) * 4;
	const dscp = data[offset + 1] >> 2;
	const ecn = data[offset + 1] & 0x03;
	const totalLength = (data[offset + 2] << 8) | data[offset + 3];
	const identification = (data[offset + 4] << 8) | data[offset + 5];
	const flagsFragment = (data[offset + 6] << 8) | data[offset + 7];
	const flags = {
		reserved: !!(flagsFragment & 0x8000),
		dontFragment: !!(flagsFragment & 0x4000),
		moreFragments: !!(flagsFragment & 0x2000),
	};
	const fragmentOffset = flagsFragment & 0x1fff;
	const ttl = data[offset + 8];
	const protocol = data[offset + 9];
	const headerChecksum = (data[offset + 10] << 8) | data[offset + 11];
	const srcIP = `${data[offset + 12]}.${data[offset + 13]}.${data[offset + 14]}.${data[offset + 15]}`;
	const dstIP = `${data[offset + 16]}.${data[offset + 17]}.${data[offset + 18]}.${data[offset + 19]}`;

	pkt.layers.ipv4 = {
		version: 4,
		headerLength: ihl,
		dscp, ecn,
		totalLength,
		identification,
		flags,
		fragmentOffset,
		ttl,
		protocol,
		protocolName: IP_PROTOCOLS[protocol] || `Unknown(${protocol})`,
		headerChecksum: `0x${headerChecksum.toString(16).padStart(4, '0')}`,
		src: srcIP,
		dst: dstIP,
	};

	pkt.protocol = pkt.layers.ipv4.protocolName;
	pkt.info = `${srcIP} → ${dstIP}`;

	// Check for warnings
	if (ttl <= 1) pkt.warnings.push(`Very low TTL: ${ttl}`);
	if (flags.moreFragments || fragmentOffset > 0) pkt.warnings.push('IP fragmented');

	// Dispatch to L4
	const l4Offset = offset + ihl;
	switch (protocol) {
		case 6: decodeTCP(data, l4Offset, pkt, srcIP, dstIP); break;
		case 17: decodeUDP(data, l4Offset, pkt, srcIP, dstIP); break;
		case 1: decodeICMP(data, l4Offset, pkt, srcIP, dstIP); break;
		default:
			pkt.info += ` | Protocol ${protocol} (${IP_PROTOCOLS[protocol] || 'Unknown'})`;
			pkt.flowId = `${srcIP}-${dstIP}-${protocol}`;
	}
}

// ── Layer 3: IPv6 ──────────────────────────────────────────────────────────────

function decodeIPv6(data, offset, pkt) {
	if (offset + 40 > data.length) return;

	const vtcfl = (data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
	const trafficClass = (vtcfl >> 20) & 0xff;
	const flowLabel = vtcfl & 0xfffff;
	const payloadLength = (data[offset + 4] << 8) | data[offset + 5];
	const nextHeader = data[offset + 6];
	const hopLimit = data[offset + 7];

	const srcIP = formatIPv6(data, offset + 8);
	const dstIP = formatIPv6(data, offset + 24);

	pkt.layers.ipv6 = {
		version: 6,
		trafficClass,
		flowLabel,
		payloadLength,
		nextHeader,
		nextHeaderName: IP_PROTOCOLS[nextHeader] || `Unknown(${nextHeader})`,
		hopLimit,
		src: srcIP,
		dst: dstIP,
	};

	pkt.protocol = pkt.layers.ipv6.nextHeaderName;
	pkt.info = `${srcIP} → ${dstIP}`;

	if (hopLimit <= 1) pkt.warnings.push(`Very low Hop Limit: ${hopLimit}`);

	const l4Offset = offset + 40;
	switch (nextHeader) {
		case 6: decodeTCP(data, l4Offset, pkt, srcIP, dstIP); break;
		case 17: decodeUDP(data, l4Offset, pkt, srcIP, dstIP); break;
		case 58: decodeICMPv6(data, l4Offset, pkt, srcIP, dstIP); break;
		default:
			pkt.info += ` | Next Header ${nextHeader}`;
			pkt.flowId = `${srcIP}-${dstIP}-${nextHeader}`;
	}
}

// ── Layer 3: ARP ───────────────────────────────────────────────────────────────

function decodeARP(data, offset, pkt) {
	if (offset + 28 > data.length) return;

	const hwType = (data[offset] << 8) | data[offset + 1];
	const protoType = (data[offset + 2] << 8) | data[offset + 3];
	const hwLen = data[offset + 4];
	const protoLen = data[offset + 5];
	const opcode = (data[offset + 6] << 8) | data[offset + 7];

	const senderMac = formatMac(data, offset + 8);
	const senderIP = `${data[offset + 14]}.${data[offset + 15]}.${data[offset + 16]}.${data[offset + 17]}`;
	const targetMac = formatMac(data, offset + 18);
	const targetIP = `${data[offset + 24]}.${data[offset + 25]}.${data[offset + 26]}.${data[offset + 27]}`;

	const opName = opcode === 1 ? 'Request' : opcode === 2 ? 'Reply' : `Unknown(${opcode})`;

	pkt.layers.arp = {
		hardwareType: hwType,
		protocolType: protoType,
		hardwareSize: hwLen,
		protocolSize: protoLen,
		opcode,
		opcodeName: opName,
		senderMac, senderIP,
		targetMac, targetIP,
	};

	pkt.protocol = 'ARP';
	if (opcode === 1) {
		pkt.info = `Who has ${targetIP}? Tell ${senderIP}`;
	} else if (opcode === 2) {
		pkt.info = `${senderIP} is at ${senderMac}`;
	} else {
		pkt.info = `ARP ${opName}: ${senderIP} → ${targetIP}`;
	}
	pkt.flowId = `arp-${senderIP}-${targetIP}`;
}

// ── Layer 4: TCP ───────────────────────────────────────────────────────────────

function decodeTCP(data, offset, pkt, srcIP, dstIP) {
	if (offset + 20 > data.length) return;

	const srcPort = (data[offset] << 8) | data[offset + 1];
	const dstPort = (data[offset + 2] << 8) | data[offset + 3];
	const seqNum = ((data[offset + 4] << 24) | (data[offset + 5] << 16) | (data[offset + 6] << 8) | data[offset + 7]) >>> 0;
	const ackNum = ((data[offset + 8] << 24) | (data[offset + 9] << 16) | (data[offset + 10] << 8) | data[offset + 11]) >>> 0;
	const dataOffsetByte = data[offset + 12];
	const headerLen = ((dataOffsetByte >> 4) & 0x0f) * 4;
	const flagsByte = data[offset + 13];
	const windowSize = (data[offset + 14] << 8) | data[offset + 15];
	const checksum = (data[offset + 16] << 8) | data[offset + 17];
	const urgentPtr = (data[offset + 18] << 8) | data[offset + 19];

	// Decode flags
	const flags = [];
	for (const [bit, name] of Object.entries(TCP_FLAGS)) {
		if (flagsByte & Number(bit)) flags.push(name);
	}

	// Parse TCP options
	const options = [];
	if (headerLen > 20 && offset + headerLen <= data.length) {
		let optOffset = offset + 20;
		while (optOffset < offset + headerLen) {
			const kind = data[optOffset];
			if (kind === 0) break; // End of Options
			if (kind === 1) { optOffset++; continue; } // NOP
			if (optOffset + 1 >= data.length) break;
			const optLen = data[optOffset + 1];
			if (optLen < 2 || optOffset + optLen > data.length) break;

			switch (kind) {
				case 2: // MSS
					if (optLen === 4) options.push({ kind: 'MSS', value: (data[optOffset + 2] << 8) | data[optOffset + 3] });
					break;
				case 3: // Window Scale
					if (optLen === 3) options.push({ kind: 'Window Scale', value: data[optOffset + 2] });
					break;
				case 4: // SACK Permitted
					options.push({ kind: 'SACK Permitted', value: true });
					break;
				case 8: // Timestamps
					if (optLen === 10) {
						options.push({
							kind: 'Timestamps',
							tsval: ((data[optOffset + 2] << 24) | (data[optOffset + 3] << 16) | (data[optOffset + 4] << 8) | data[optOffset + 5]) >>> 0,
							tsecr: ((data[optOffset + 6] << 24) | (data[optOffset + 7] << 16) | (data[optOffset + 8] << 8) | data[optOffset + 9]) >>> 0,
						});
					}
					break;
				default:
					options.push({ kind: `Unknown(${kind})`, length: optLen });
			}
			optOffset += optLen;
		}
	}

	const payloadLen = Math.max(0, (pkt.layers.ipv4?.totalLength || pkt.layers.ipv6?.payloadLength || 0) - (pkt.layers.ipv4?.headerLength || 40) - headerLen);

	pkt.layers.tcp = {
		srcPort, dstPort,
		seqNum, ackNum,
		headerLength: headerLen,
		flags, flagsByte,
		windowSize, checksum: `0x${checksum.toString(16).padStart(4, '0')}`,
		urgentPointer: urgentPtr,
		options,
		payloadLength: payloadLen,
	};

	// Build flow ID (normalised: lower IP:port first)
	const src = `${srcIP}:${srcPort}`;
	const dst = `${dstIP}:${dstPort}`;
	pkt.flowId = src < dst ? `${src}-${dst}-TCP` : `${dst}-${src}-TCP`;

	// Determine application protocol
	const appProto = identifyAppProtocol(srcPort, dstPort, flags);
	const flagStr = `[${flags.join(', ')}]`;
	const portInfo = `${srcPort} → ${dstPort}`;

	pkt.protocol = 'TCP';
	pkt.info = `${srcIP}:${srcPort} → ${dstIP}:${dstPort} ${flagStr} Seq=${seqNum} Ack=${ackNum} Win=${windowSize} Len=${payloadLen}`;

	// Check for issues
	if (flags.includes('RST')) pkt.warnings.push('TCP Reset');
	if (flags.includes('SYN') && flags.includes('FIN')) pkt.warnings.push('Suspicious: SYN+FIN');
	if (windowSize === 0 && !flags.includes('RST') && !flags.includes('FIN')) pkt.warnings.push('Zero window (possible flow control issue)');

	// Attempt L7 decode
	const payloadOffset = offset + headerLen;
	if (payloadLen > 0 && payloadOffset + payloadLen <= data.length) {
		decodeTCPPayload(data, payloadOffset, payloadLen, srcPort, dstPort, pkt);
	}
}

// ── Layer 4: UDP ───────────────────────────────────────────────────────────────

function decodeUDP(data, offset, pkt, srcIP, dstIP) {
	if (offset + 8 > data.length) return;

	const srcPort = (data[offset] << 8) | data[offset + 1];
	const dstPort = (data[offset + 2] << 8) | data[offset + 3];
	const length = (data[offset + 4] << 8) | data[offset + 5];
	const checksum = (data[offset + 6] << 8) | data[offset + 7];

	pkt.layers.udp = {
		srcPort, dstPort,
		length,
		checksum: `0x${checksum.toString(16).padStart(4, '0')}`,
		payloadLength: Math.max(0, length - 8),
	};

	const src = `${srcIP}:${srcPort}`;
	const dst = `${dstIP}:${dstPort}`;
	pkt.flowId = src < dst ? `${src}-${dst}-UDP` : `${dst}-${src}-UDP`;

	pkt.protocol = 'UDP';
	pkt.info = `${srcIP}:${srcPort} → ${dstIP}:${dstPort} Len=${length - 8}`;

	// Attempt L7 decode
	const payloadOffset = offset + 8;
	const payloadLen = Math.min(length - 8, data.length - payloadOffset);

	if (payloadLen > 0) {
		if (srcPort === 53 || dstPort === 53) {
			decodeDNS(data, payloadOffset, payloadLen, pkt);
		} else if (srcPort === 67 || srcPort === 68 || dstPort === 67 || dstPort === 68) {
			decodeDHCP(data, payloadOffset, payloadLen, pkt);
		} else if (srcPort === 123 || dstPort === 123) {
			pkt.protocol = 'NTP';
			pkt.info = `NTP ${srcIP}:${srcPort} → ${dstIP}:${dstPort}`;
		} else if (srcPort === 500 || dstPort === 500 || srcPort === 4500 || dstPort === 4500) {
			pkt.protocol = 'IKE/IPsec';
			pkt.info = `IKE ${srcIP}:${srcPort} → ${dstIP}:${dstPort}`;
		} else if (dstPort === 2408 || srcPort === 2408) {
			pkt.protocol = 'WARP';
			pkt.info = `Cloudflare WARP ${srcIP}:${srcPort} → ${dstIP}:${dstPort} Len=${payloadLen}`;
		}
	}
}

// ── Layer 4: ICMP ──────────────────────────────────────────────────────────────

function decodeICMP(data, offset, pkt, srcIP, dstIP) {
	if (offset + 4 > data.length) return;

	const type = data[offset];
	const code = data[offset + 1];
	const checksum = (data[offset + 2] << 8) | data[offset + 3];

	const typeName = ICMP_TYPES[type] || `Type ${type}`;
	let codeDesc = '';
	if (type === 3) codeDesc = ICMP_DEST_UNREACHABLE_CODES[code] || `Code ${code}`;

	let extra = {};
	if ((type === 0 || type === 8) && offset + 8 <= data.length) {
		extra.identifier = (data[offset + 4] << 8) | data[offset + 5];
		extra.sequenceNumber = (data[offset + 6] << 8) | data[offset + 7];
	}

	pkt.layers.icmp = {
		type, code, typeName, codeDescription: codeDesc,
		checksum: `0x${checksum.toString(16).padStart(4, '0')}`,
		...extra,
	};

	pkt.protocol = 'ICMP';
	pkt.info = `${srcIP} → ${dstIP} ${typeName}`;
	if (codeDesc) pkt.info += ` (${codeDesc})`;
	if (extra.identifier !== undefined) pkt.info += ` id=0x${extra.identifier.toString(16)} seq=${extra.sequenceNumber}`;
	pkt.flowId = `${srcIP}-${dstIP}-ICMP`;

	if (type === 3) pkt.warnings.push(`ICMP Destination Unreachable: ${codeDesc || `code ${code}`}`);
	if (type === 11) pkt.warnings.push('ICMP Time Exceeded (TTL expired)');
}

// ── Layer 4: ICMPv6 ────────────────────────────────────────────────────────────

function decodeICMPv6(data, offset, pkt, srcIP, dstIP) {
	if (offset + 4 > data.length) return;

	const type = data[offset];
	const code = data[offset + 1];
	const checksum = (data[offset + 2] << 8) | data[offset + 3];

	let typeName = `Type ${type}`;
	if (type === 1) typeName = 'Destination Unreachable';
	else if (type === 2) typeName = 'Packet Too Big';
	else if (type === 3) typeName = 'Time Exceeded';
	else if (type === 128) typeName = 'Echo Request';
	else if (type === 129) typeName = 'Echo Reply';
	else if (type === 133) typeName = 'Router Solicitation';
	else if (type === 134) typeName = 'Router Advertisement';
	else if (type === 135) typeName = 'Neighbor Solicitation';
	else if (type === 136) typeName = 'Neighbor Advertisement';

	pkt.layers.icmpv6 = { type, code, typeName, checksum: `0x${checksum.toString(16).padStart(4, '0')}` };
	pkt.protocol = 'ICMPv6';
	pkt.info = `${srcIP} → ${dstIP} ${typeName}`;
	pkt.flowId = `${srcIP}-${dstIP}-ICMPv6`;
}

// ── Layer 7: TCP Payload ───────────────────────────────────────────────────────

function decodeTCPPayload(data, offset, length, srcPort, dstPort, pkt) {
	if (length < 2) return;

	// TLS detection
	const firstByte = data[offset];
	if (firstByte >= 20 && firstByte <= 23 && length >= 5) {
		const possibleVersion = (data[offset + 1] << 8) | data[offset + 2];
		if (TLS_VERSIONS[possibleVersion] || possibleVersion === 0x0301) {
			decodeTLS(data, offset, length, pkt);
			return;
		}
	}

	// HTTP detection
	const first4 = String.fromCharCode(data[offset], data[offset + 1], data[offset + 2], data[offset + 3]);
	if (first4 === 'GET ' || first4 === 'POST' || first4 === 'PUT ' || first4 === 'DELE' ||
		first4 === 'HEAD' || first4 === 'OPTI' || first4 === 'PATC' || first4 === 'HTTP') {
		decodeHTTP(data, offset, length, pkt);
		return;
	}

	// SSH banner detection
	if (length >= 4 && first4 === 'SSH-') {
		pkt.protocol = 'SSH';
		const bannerEnd = Math.min(offset + length, offset + 255);
		let banner = '';
		for (let i = offset; i < bannerEnd; i++) {
			const c = data[i];
			if (c === 0x0a || c === 0x0d) break;
			banner += String.fromCharCode(c);
		}
		pkt.layers.ssh = { banner };
		pkt.info = `SSH: ${banner}`;
		return;
	}

	// DNS over TCP (port 53)
	if (srcPort === 53 || dstPort === 53) {
		// TCP DNS has 2-byte length prefix
		if (length >= 14) {
			const dnsLen = (data[offset] << 8) | data[offset + 1];
			if (dnsLen <= length - 2) {
				decodeDNS(data, offset + 2, dnsLen, pkt);
				return;
			}
		}
	}

	// If common port, label it
	const appPort = WELL_KNOWN_PORTS[dstPort] || WELL_KNOWN_PORTS[srcPort];
	if (appPort) {
		pkt.info += ` [${appPort}]`;
	}
}

// ── Layer 7: DNS ───────────────────────────────────────────────────────────────

function decodeDNS(data, offset, length, pkt) {
	if (length < 12) return;

	const txid = (data[offset] << 8) | data[offset + 1];
	const flagsWord = (data[offset + 2] << 8) | data[offset + 3];
	const isResponse = !!(flagsWord & 0x8000);
	const opcode = (flagsWord >> 11) & 0x0f;
	const aa = !!(flagsWord & 0x0400);
	const tc = !!(flagsWord & 0x0200);
	const rd = !!(flagsWord & 0x0100);
	const ra = !!(flagsWord & 0x0080);
	const rcode = flagsWord & 0x000f;
	const qdCount = (data[offset + 4] << 8) | data[offset + 5];
	const anCount = (data[offset + 6] << 8) | data[offset + 7];
	const nsCount = (data[offset + 8] << 8) | data[offset + 9];
	const arCount = (data[offset + 10] << 8) | data[offset + 11];

	const dns = {
		transactionId: `0x${txid.toString(16).padStart(4, '0')}`,
		isResponse,
		opcode,
		flags: { authoritative: aa, truncated: tc, recursionDesired: rd, recursionAvailable: ra },
		rcode,
		rcodeName: DNS_RCODES[rcode] || `Unknown(${rcode})`,
		questions: [],
		answers: [],
		qdCount, anCount, nsCount, arCount,
	};

	// Parse questions
	let pos = offset + 12;
	for (let i = 0; i < qdCount && pos < offset + length; i++) {
		const { name, newPos } = decodeDNSName(data, pos, offset);
		if (newPos + 4 > offset + length) break;
		const qtype = (data[newPos] << 8) | data[newPos + 1];
		const qclass = (data[newPos + 2] << 8) | data[newPos + 3];
		dns.questions.push({
			name,
			type: qtype,
			typeName: DNS_TYPES[qtype] || `TYPE${qtype}`,
			class: qclass,
			className: DNS_CLASSES[qclass] || `CLASS${qclass}`,
		});
		pos = newPos + 4;
	}

	// Parse answers (for responses)
	if (isResponse) {
		for (let i = 0; i < anCount && pos < offset + length - 10; i++) {
			const { name, newPos } = decodeDNSName(data, pos, offset);
			if (newPos + 10 > offset + length) break;
			const rtype = (data[newPos] << 8) | data[newPos + 1];
			const rclass = (data[newPos + 2] << 8) | data[newPos + 3];
			const ttl = ((data[newPos + 4] << 24) | (data[newPos + 5] << 16) | (data[newPos + 6] << 8) | data[newPos + 7]) >>> 0;
			const rdlength = (data[newPos + 8] << 8) | data[newPos + 9];

			let rdata = '';
			const rdStart = newPos + 10;
			if (rdStart + rdlength <= offset + length) {
				if (rtype === 1 && rdlength === 4) {
					rdata = `${data[rdStart]}.${data[rdStart + 1]}.${data[rdStart + 2]}.${data[rdStart + 3]}`;
				} else if (rtype === 28 && rdlength === 16) {
					rdata = formatIPv6(data, rdStart);
				} else if (rtype === 5 || rtype === 2 || rtype === 12) {
					const { name: rdName } = decodeDNSName(data, rdStart, offset);
					rdata = rdName;
				} else {
					rdata = `[${rdlength} bytes]`;
				}
			}

			dns.answers.push({
				name, type: rtype, typeName: DNS_TYPES[rtype] || `TYPE${rtype}`,
				class: rclass, ttl, rdata,
			});
			pos = newPos + 10 + rdlength;
		}
	}

	pkt.layers.dns = dns;
	pkt.protocol = 'DNS';

	const queryName = dns.questions[0]?.name || '';
	const queryType = dns.questions[0]?.typeName || '';

	if (isResponse) {
		const answerData = dns.answers.length > 0 ? dns.answers.map(a => a.rdata).join(', ') : 'No answers';
		pkt.info = `DNS Response 0x${txid.toString(16)} ${dns.rcodeName} ${queryType} ${queryName} → ${answerData}`;
		if (rcode !== 0) pkt.warnings.push(`DNS error: ${dns.rcodeName}`);
		if (tc) pkt.warnings.push('DNS response truncated');
	} else {
		pkt.info = `DNS Query 0x${txid.toString(16)} ${queryType} ${queryName}`;
	}
}

function decodeDNSName(data, pos, baseOffset) {
	const parts = [];
	let jumped = false;
	let originalPos = pos;
	let safety = 0;

	while (pos < data.length && safety < 128) {
		safety++;
		const len = data[pos];
		if (len === 0) { pos++; break; }

		if ((len & 0xc0) === 0xc0) {
			// Compression pointer
			if (pos + 1 >= data.length) break;
			const ptr = ((len & 0x3f) << 8) | data[pos + 1];
			if (!jumped) originalPos = pos + 2;
			jumped = true;
			pos = baseOffset + ptr;
			continue;
		}

		pos++;
		if (pos + len > data.length) break;
		let label = '';
		for (let i = 0; i < len; i++) {
			label += String.fromCharCode(data[pos + i]);
		}
		parts.push(label);
		pos += len;
	}

	return { name: parts.join('.') || '<root>', newPos: jumped ? originalPos : pos };
}

// ── Layer 7: TLS ───────────────────────────────────────────────────────────────

function decodeTLS(data, offset, length, pkt) {
	if (length < 5) return;

	const contentType = data[offset];
	const version = (data[offset + 1] << 8) | data[offset + 2];
	const recordLen = (data[offset + 3] << 8) | data[offset + 4];

	const tls = {
		contentType,
		contentTypeName: TLS_CONTENT_TYPES[contentType] || `Unknown(${contentType})`,
		version,
		versionName: TLS_VERSIONS[version] || `Unknown(0x${version.toString(16)})`,
		recordLength: recordLen,
	};

	pkt.protocol = tls.versionName || 'TLS';

	// Parse Handshake messages
	if (contentType === 22 && length >= 10) {
		const hsType = data[offset + 5];
		const hsLen = (data[offset + 6] << 16) | (data[offset + 7] << 8) | data[offset + 8];

		tls.handshakeType = hsType;
		tls.handshakeTypeName = TLS_HANDSHAKE_TYPES[hsType] || `Unknown(${hsType})`;

		if (hsType === 1 && length >= 43) {
			// ClientHello - extract SNI
			const clientVersion = (data[offset + 9] << 8) | data[offset + 10];
			tls.clientVersion = TLS_VERSIONS[clientVersion] || `0x${clientVersion.toString(16)}`;

			// Skip past random (32 bytes) + session ID + cipher suites + compression to find extensions
			let pos = offset + 11 + 32; // past type(1) + length(3) + version(2) + random(32)
			if (pos < offset + length) {
				const sessionIdLen = data[pos];
				pos += 1 + sessionIdLen;

				if (pos + 2 < offset + length) {
					const cipherSuitesLen = (data[pos] << 8) | data[pos + 1];
					tls.cipherSuitesCount = cipherSuitesLen / 2;
					pos += 2 + cipherSuitesLen;

					if (pos + 1 < offset + length) {
						const compMethodsLen = data[pos];
						pos += 1 + compMethodsLen;

						// Extensions
						if (pos + 2 < offset + length) {
							const extLen = (data[pos] << 8) | data[pos + 1];
							pos += 2;

							const extEnd = Math.min(pos + extLen, offset + length);
							while (pos + 4 < extEnd) {
								const extType = (data[pos] << 8) | data[pos + 1];
								const extDataLen = (data[pos + 2] << 8) | data[pos + 3];
								pos += 4;

								if (extType === 0 && extDataLen >= 5 && pos + extDataLen <= extEnd) {
									// SNI extension
									const sniListLen = (data[pos] << 8) | data[pos + 1];
									const sniType = data[pos + 2];
									const sniLen = (data[pos + 3] << 8) | data[pos + 4];
									if (sniType === 0 && sniLen > 0 && pos + 5 + sniLen <= extEnd) {
										let sni = '';
										for (let i = 0; i < sniLen; i++) {
											sni += String.fromCharCode(data[pos + 5 + i]);
										}
										tls.sni = sni;
									}
								} else if (extType === 16 && extDataLen >= 2 && pos + extDataLen <= extEnd) {
									// ALPN extension
									const alpnListLen = (data[pos] << 8) | data[pos + 1];
									const protocols = [];
									let alpnPos = pos + 2;
									const alpnEnd = Math.min(alpnPos + alpnListLen, extEnd);
									while (alpnPos < alpnEnd) {
										const protoLen = data[alpnPos];
										alpnPos++;
										if (alpnPos + protoLen <= alpnEnd) {
											let proto = '';
											for (let i = 0; i < protoLen; i++) proto += String.fromCharCode(data[alpnPos + i]);
											protocols.push(proto);
										}
										alpnPos += protoLen;
									}
									tls.alpn = protocols;
								}
								pos += extDataLen;
							}
						}
					}
				}
			}
		} else if (hsType === 2 && length >= 43) {
			// ServerHello
			const serverVersion = (data[offset + 9] << 8) | data[offset + 10];
			tls.serverVersion = TLS_VERSIONS[serverVersion] || `0x${serverVersion.toString(16)}`;
		}

		pkt.info = `${tls.versionName} ${tls.handshakeTypeName}`;
		if (tls.sni) pkt.info += ` SNI=${tls.sni}`;
		if (tls.alpn) pkt.info += ` ALPN=[${tls.alpn.join(',')}]`;
	} else if (contentType === 23) {
		pkt.info = `${tls.versionName} Application Data [${recordLen} bytes]`;
	} else if (contentType === 21) {
		pkt.info = `${tls.versionName} Alert`;
		pkt.warnings.push('TLS Alert received');
	} else if (contentType === 20) {
		pkt.info = `${tls.versionName} Change Cipher Spec`;
	} else {
		pkt.info = `${tls.versionName} ${tls.contentTypeName} [${recordLen} bytes]`;
	}

	pkt.layers.tls = tls;
}

// ── Layer 7: HTTP ──────────────────────────────────────────────────────────────

function decodeHTTP(data, offset, length, pkt) {
	// Read the first line + headers (up to first \r\n\r\n or reasonable limit)
	const maxScan = Math.min(length, 4096);
	let text = '';
	for (let i = 0; i < maxScan; i++) {
		const c = data[offset + i];
		if (c === 0) break;
		text += String.fromCharCode(c);
	}

	const lines = text.split('\r\n');
	const firstLine = lines[0] || '';

	const http = {
		firstLine,
		headers: {},
		isRequest: false,
		isResponse: false,
	};

	// Parse request
	const reqMatch = firstLine.match(/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+(\S+)\s+(HTTP\/[\d.]+)/);
	if (reqMatch) {
		http.isRequest = true;
		http.method = reqMatch[1];
		http.uri = reqMatch[2];
		http.version = reqMatch[3];
		pkt.protocol = 'HTTP';
		pkt.info = `HTTP ${http.method} ${http.uri} ${http.version}`;
	}

	// Parse response
	const respMatch = firstLine.match(/^(HTTP\/[\d.]+)\s+(\d+)\s*(.*)/);
	if (respMatch) {
		http.isResponse = true;
		http.version = respMatch[1];
		http.statusCode = parseInt(respMatch[2], 10);
		http.statusText = respMatch[3];
		pkt.protocol = 'HTTP';
		pkt.info = `HTTP ${http.statusCode} ${http.statusText}`;
	}

	// Parse headers
	for (let i = 1; i < lines.length; i++) {
		if (lines[i] === '') break;
		const colonIdx = lines[i].indexOf(':');
		if (colonIdx > 0) {
			const key = lines[i].substring(0, colonIdx).trim();
			const value = lines[i].substring(colonIdx + 1).trim();
			http.headers[key] = value;
		}
	}

	// Detect Cloudflare-specific headers
	if (http.headers['CF-Connecting-IP'] || http.headers['cf-connecting-ip']) {
		http.cloudflare = true;
	}
	if (http.headers['CF-RAY'] || http.headers['cf-ray']) {
		http.cfRay = http.headers['CF-RAY'] || http.headers['cf-ray'];
	}

	pkt.layers.http = http;

	// Add content info to summary
	const contentType = http.headers['Content-Type'] || http.headers['content-type'];
	const contentLength = http.headers['Content-Length'] || http.headers['content-length'];
	if (contentType) pkt.info += ` [${contentType}]`;
	if (contentLength) pkt.info += ` (${contentLength} bytes)`;
	if (http.headers['Host'] || http.headers['host']) pkt.info += ` Host: ${http.headers['Host'] || http.headers['host']}`;
}

// ── Layer 7: DHCP ──────────────────────────────────────────────────────────────

function decodeDHCP(data, offset, length, pkt) {
	if (length < 240) return; // Minimum DHCP packet size

	const op = data[offset];
	const htype = data[offset + 1];
	const hlen = data[offset + 2];
	const xid = ((data[offset + 4] << 24) | (data[offset + 5] << 16) | (data[offset + 6] << 8) | data[offset + 7]) >>> 0;
	const ciaddr = `${data[offset + 12]}.${data[offset + 13]}.${data[offset + 14]}.${data[offset + 15]}`;
	const yiaddr = `${data[offset + 16]}.${data[offset + 17]}.${data[offset + 18]}.${data[offset + 19]}`;
	const siaddr = `${data[offset + 20]}.${data[offset + 21]}.${data[offset + 22]}.${data[offset + 23]}`;
	const chaddr = formatMac(data, offset + 28);

	const dhcp = {
		op: op === 1 ? 'Request' : op === 2 ? 'Reply' : `Unknown(${op})`,
		transactionId: `0x${xid.toString(16).padStart(8, '0')}`,
		clientIP: ciaddr,
		yourIP: yiaddr,
		serverIP: siaddr,
		clientMAC: chaddr,
	};

	// Parse DHCP options (after magic cookie at offset+236)
	const magicCookie = ((data[offset + 236] << 24) | (data[offset + 237] << 16) | (data[offset + 238] << 8) | data[offset + 239]) >>> 0;
	if (magicCookie === 0x63825363) {
		let optPos = offset + 240;
		while (optPos < offset + length) {
			const optCode = data[optPos];
			if (optCode === 255) break; // End
			if (optCode === 0) { optPos++; continue; } // Pad

			const optLen = data[optPos + 1];
			optPos += 2;

			if (optCode === 53 && optLen === 1) {
				dhcp.messageType = DHCP_MESSAGE_TYPES[data[optPos]] || `Unknown(${data[optPos]})`;
			} else if (optCode === 54 && optLen === 4) {
				dhcp.dhcpServer = `${data[optPos]}.${data[optPos + 1]}.${data[optPos + 2]}.${data[optPos + 3]}`;
			} else if (optCode === 51 && optLen === 4) {
				dhcp.leaseTime = ((data[optPos] << 24) | (data[optPos + 1] << 16) | (data[optPos + 2] << 8) | data[optPos + 3]) >>> 0;
			}
			optPos += optLen;
		}
	}

	pkt.layers.dhcp = dhcp;
	pkt.protocol = 'DHCP';
	pkt.info = `DHCP ${dhcp.messageType || dhcp.op} Transaction ID ${dhcp.transactionId}`;
	if (dhcp.messageType === 'Offer' || dhcp.messageType === 'ACK') {
		pkt.info += ` IP=${yiaddr}`;
	}
}

// ── Flow tracking ──────────────────────────────────────────────────────────────

function buildFlows(packets) {
	const flows = {};

	for (const pkt of packets) {
		if (!pkt.flowId) continue;

		if (!flows[pkt.flowId]) {
			const srcIP = pkt.layers.ipv4?.src || pkt.layers.ipv6?.src || '';
			const dstIP = pkt.layers.ipv4?.dst || pkt.layers.ipv6?.dst || '';
			const srcPort = pkt.layers.tcp?.srcPort || pkt.layers.udp?.srcPort || 0;
			const dstPort = pkt.layers.tcp?.dstPort || pkt.layers.udp?.dstPort || 0;
			const proto = pkt.layers.tcp ? 'TCP' : pkt.layers.udp ? 'UDP' : pkt.layers.icmp ? 'ICMP' : 'Other';

			flows[pkt.flowId] = {
				id: pkt.flowId,
				srcIP, dstIP,
				srcPort, dstPort,
				protocol: proto,
				appProtocol: '',
				packetNumbers: [],
				bytesAtoB: 0,
				bytesBtoA: 0,
				packetsAtoB: 0,
				packetsBtoA: 0,
				startTime: pkt.timestamp,
				endTime: pkt.timestamp,
				tcpState: proto === 'TCP' ? 'INIT' : null,
				warnings: [],
			};
		}

		const flow = flows[pkt.flowId];
		flow.packetNumbers.push(pkt.number);
		flow.endTime = pkt.timestamp;

		// Determine direction (A = first seen src)
		const isAtoB = (pkt.layers.ipv4?.src || pkt.layers.ipv6?.src || '') === flow.srcIP;
		if (isAtoB) {
			flow.bytesAtoB += pkt.capturedLength;
			flow.packetsAtoB++;
		} else {
			flow.bytesBtoA += pkt.capturedLength;
			flow.packetsBtoA++;
		}

		// Track TCP state
		if (pkt.layers.tcp && flow.tcpState) {
			const flags = pkt.layers.tcp.flags;
			if (flags.includes('SYN') && !flags.includes('ACK')) flow.tcpState = 'SYN_SENT';
			else if (flags.includes('SYN') && flags.includes('ACK')) flow.tcpState = 'SYN_RCVD';
			else if (flow.tcpState === 'SYN_RCVD' && flags.includes('ACK')) flow.tcpState = 'ESTABLISHED';
			else if (flags.includes('FIN')) flow.tcpState = flow.tcpState === 'FIN_WAIT' ? 'CLOSING' : 'FIN_WAIT';
			else if (flags.includes('RST')) {
				flow.tcpState = 'RESET';
				flow.warnings.push('Connection reset');
			}
		}

		// Detect app protocol from highest layer
		if (pkt.layers.tls) flow.appProtocol = 'TLS';
		else if (pkt.layers.http) flow.appProtocol = 'HTTP';
		else if (pkt.layers.dns) flow.appProtocol = 'DNS';
		else if (pkt.layers.dhcp) flow.appProtocol = 'DHCP';
		else if (pkt.layers.ssh) flow.appProtocol = 'SSH';
	}

	return flows;
}

// ── Statistics ─────────────────────────────────────────────────────────────────

function buildStatistics(packets, flows, metadata) {
	const stats = {
		totalPackets: packets.length,
		totalBytes: 0,
		capturedPackets: metadata.totalPackets || packets.length,
		duration: 0,
		avgPacketSize: 0,
		protocols: {},
		protocolHierarchy: {},
		topTalkers: {},
		portDistribution: {},
		packetSizeDistribution: { '<64': 0, '64-127': 0, '128-255': 0, '256-511': 0, '512-1023': 0, '1024-1517': 0, '>1517': 0 },
		warningsSummary: {},
		dnsQueries: [],
		tlsConnections: [],
		httpRequests: [],
	};

	if (packets.length === 0) return stats;

	const firstTs = packets[0].timestamp;
	const lastTs = packets[packets.length - 1].timestamp;
	stats.duration = lastTs - firstTs;

	for (const pkt of packets) {
		stats.totalBytes += pkt.capturedLength;

		// Protocol distribution
		stats.protocols[pkt.protocol] = (stats.protocols[pkt.protocol] || 0) + 1;

		// Protocol hierarchy (layer chain)
		const chain = pkt.layers.frame?.protocols || pkt.protocol;
		stats.protocolHierarchy[chain] = (stats.protocolHierarchy[chain] || 0) + 1;

		// Top talkers
		const src = pkt.layers.ipv4?.src || pkt.layers.ipv6?.src;
		const dst = pkt.layers.ipv4?.dst || pkt.layers.ipv6?.dst;
		if (src) stats.topTalkers[src] = (stats.topTalkers[src] || 0) + pkt.capturedLength;
		if (dst) stats.topTalkers[dst] = (stats.topTalkers[dst] || 0) + pkt.capturedLength;

		// Port distribution
		const dPort = pkt.layers.tcp?.dstPort || pkt.layers.udp?.dstPort;
		if (dPort) {
			const label = WELL_KNOWN_PORTS[dPort] || `Port ${dPort}`;
			stats.portDistribution[label] = (stats.portDistribution[label] || 0) + 1;
		}

		// Packet size distribution
		const sz = pkt.capturedLength;
		if (sz < 64) stats.packetSizeDistribution['<64']++;
		else if (sz < 128) stats.packetSizeDistribution['64-127']++;
		else if (sz < 256) stats.packetSizeDistribution['128-255']++;
		else if (sz < 512) stats.packetSizeDistribution['256-511']++;
		else if (sz < 1024) stats.packetSizeDistribution['512-1023']++;
		else if (sz < 1518) stats.packetSizeDistribution['1024-1517']++;
		else stats.packetSizeDistribution['>1517']++;

		// Warnings summary
		for (const w of pkt.warnings) {
			stats.warningsSummary[w] = (stats.warningsSummary[w] || 0) + 1;
		}

		// DNS queries
		if (pkt.layers.dns && pkt.layers.dns.questions.length > 0) {
			stats.dnsQueries.push({
				packet: pkt.number,
				query: pkt.layers.dns.questions[0].name,
				type: pkt.layers.dns.questions[0].typeName,
				isResponse: pkt.layers.dns.isResponse,
				rcode: pkt.layers.dns.rcodeName,
				answers: pkt.layers.dns.answers?.map(a => a.rdata) || [],
			});
		}

		// TLS connections
		if (pkt.layers.tls?.sni) {
			stats.tlsConnections.push({
				packet: pkt.number,
				sni: pkt.layers.tls.sni,
				version: pkt.layers.tls.versionName,
				alpn: pkt.layers.tls.alpn,
			});
		}

		// HTTP requests
		if (pkt.layers.http?.isRequest) {
			stats.httpRequests.push({
				packet: pkt.number,
				method: pkt.layers.http.method,
				uri: pkt.layers.http.uri,
				host: pkt.layers.http.headers['Host'] || pkt.layers.http.headers['host'] || '',
			});
		}
	}

	stats.avgPacketSize = Math.round(stats.totalBytes / stats.totalPackets);

	// Sort top talkers by bytes (descending) and limit to top 20
	stats.topTalkers = Object.entries(stats.topTalkers)
		.sort((a, b) => b[1] - a[1])
		.slice(0, 20)
		.reduce((obj, [k, v]) => { obj[k] = v; return obj; }, {});

	return stats;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function identifyAppProtocol(srcPort, dstPort) {
	if (srcPort === 443 || dstPort === 443) return 'HTTPS';
	if (srcPort === 80 || dstPort === 80) return 'HTTP';
	if (srcPort === 53 || dstPort === 53) return 'DNS';
	if (srcPort === 22 || dstPort === 22) return 'SSH';
	if (srcPort === 2408 || dstPort === 2408) return 'WARP';
	return WELL_KNOWN_PORTS[dstPort] || WELL_KNOWN_PORTS[srcPort] || '';
}

function formatMac(data, offset) {
	const bytes = [];
	for (let i = 0; i < 6; i++) bytes.push(data[offset + i].toString(16).padStart(2, '0'));
	return bytes.join(':');
}

function formatIPv6(data, offset) {
	const groups = [];
	for (let i = 0; i < 16; i += 2) {
		groups.push(((data[offset + i] << 8) | data[offset + i + 1]).toString(16));
	}
	// Simple compression: replace longest run of :0: groups
	const full = groups.join(':');
	return full.replace(/\b(?:0:){2,}0\b/, '::').replace(/^0::/, '::').replace(/::0$/, '::');
}

function bytesToHex(data) {
	const lines = [];
	for (let i = 0; i < data.length; i += 16) {
		const hex = [];
		for (let j = 0; j < 16; j++) {
			if (i + j < data.length) {
				hex.push(data[i + j].toString(16).padStart(2, '0'));
			} else {
				hex.push('  ');
			}
		}
		lines.push({
			offset: i.toString(16).padStart(4, '0'),
			hex: hex.slice(0, 8).join(' ') + '  ' + hex.slice(8).join(' '),
			ascii: Array.from(data.slice(i, Math.min(i + 16, data.length)))
				.map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '.')
				.join(''),
		});
	}
	return lines;
}

function bytesToAscii(data) {
	return Array.from(data).map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '.').join('');
}

function formatBytes(bytes) {
	if (bytes < 1024) return `${bytes} B`;
	if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
	return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export { formatBytes, WELL_KNOWN_PORTS, DNS_TYPES };
