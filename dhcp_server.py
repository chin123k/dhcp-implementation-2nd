"""
DHCP Server Implementation using Raw Sockets

Features:
- Maintains IP pool from 192.168.1.10 to 192.168.1.100
- 60-second lease duration
- Tracks allocated IPs by MAC address
- Handles DHCPDISCOVER and DHCPREQUEST
- Uses raw UDP sockets on port 67
- Broadcast responses to port 68
- Implements proper DHCP packet structure with options
- Releases expired leases and logs events
"""

import socket
import struct
import time
import threading
import logging
import binascii

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# DHCP Message Types
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_ACK = 5

# DHCP Options
DHCP_MESSAGE_TYPE = 53
DHCP_SERVER_ID = 54
DHCP_IP_LEASE_TIME = 51
DHCP_SUBNET_MASK = 1
DHCP_ROUTER = 3
DHCP_DNS = 6
DHCP_END = 255

# DHCP Magic Cookie
DHCP_MAGIC_COOKIE = bytes([0x63, 0x82, 0x53, 0x63])

class DHCPServer:
    def __init__(self, server_ip='192.168.1.1', start_ip='192.168.1.10', end_ip='192.168.1.100', lease_time=60):
        self.logger = logging.getLogger('DHCPServer')
        self.server_ip = server_ip
        
        # IP pool management
        self.start_ip = self.ip_to_int(start_ip)
        self.end_ip = self.ip_to_int(end_ip)
        self.available_ips = list(range(self.start_ip, self.end_ip + 1))
        self.allocated_ips = {}  # {mac_address: (ip, lease_expiry_time)}
        self.lease_time = lease_time
        
        # Create the socket
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.sock.bind(('0.0.0.0', 67))
            self.logger.info(f"DHCP Server started on {server_ip} with IP pool {start_ip} - {end_ip}")
        except Exception as e:
            self.logger.error(f"Failed to create socket: {e}")
            raise
    
    def ip_to_int(self, ip):
        """Convert IP string to integer"""
        return struct.unpack('!I', socket.inet_aton(ip))[0]
    
    def int_to_ip(self, ip_int):
        """Convert integer to IP string"""
        return socket.inet_ntoa(struct.pack('!I', ip_int))
    
    def allocate_ip(self, mac_address):
        """Allocate an IP address for the given MAC address"""
        # Create a key for the MAC address
        mac_key = binascii.hexlify(mac_address).decode()
        
        # Check if this MAC already has an IP
        if mac_key in self.allocated_ips:
            ip, _ = self.allocated_ips[mac_key]
            self.logger.info(f"Reusing IP {self.int_to_ip(ip)} for MAC {mac_key}")
            # Refresh lease time
            self.allocated_ips[mac_key] = (ip, time.time() + self.lease_time)
            return ip
        
        # Allocate a new IP if available
        if not self.available_ips:
            self.logger.warning("No available IPs in the pool!")
            return None
        
        ip = self.available_ips.pop(0)
        self.allocated_ips[mac_key] = (ip, time.time() + self.lease_time)
        self.logger.info(f"Allocated IP {self.int_to_ip(ip)} to MAC {mac_key}")
        return ip
    
    def release_expired_leases(self):
        """Release expired leases back to the pool"""
        current_time = time.time()
        expired_macs = [mac for mac, (ip, expiry_time) in self.allocated_ips.items() if expiry_time < current_time]
        
        for mac in expired_macs:
            ip, _ = self.allocated_ips.pop(mac)
            self.available_ips.append(ip)
            self.logger.info(f"Released expired lease: IP {self.int_to_ip(ip)} from MAC {mac}")
    
    def create_dhcp_offer(self, xid, mac_address, yiaddr):
        """Create a DHCP OFFER packet"""
        # Header fields
        op = 2  # Boot Reply
        htype = 1  # Ethernet
        hlen = 6  # MAC address length
        hops = 0
        secs = 0
        flags = 0x8000  # Broadcast flag set
        ciaddr = 0  # Client IP address
        siaddr = self.ip_to_int(self.server_ip)  # Server IP address
        giaddr = 0  # Gateway IP address
        
        # Fill chaddr field with MAC and padding
        chaddr = mac_address + bytes([0] * (16 - len(mac_address)))  # Ensure it's 16 bytes
        
        # Server host name and Boot file name (empty)
        sname = bytes([0] * 64)
        file = bytes([0] * 128)
        
        # Create the basic packet structure
        packet = struct.pack('!BBBBIHH', op, htype, hlen, hops, xid, secs, flags)
        packet += struct.pack('!II', ciaddr, yiaddr)
        packet += struct.pack('!II', siaddr, giaddr)
        packet += chaddr
        packet += sname
        packet += file
        
        # Add DHCP magic cookie
        packet += DHCP_MAGIC_COOKIE
        
        # Add DHCP options
        packet += struct.pack('!BBB', DHCP_MESSAGE_TYPE, 1, DHCP_OFFER)  # Message Type: OFFER
        packet += struct.pack('!BBI', DHCP_SERVER_ID, 4, siaddr)  # Server Identifier
        packet += struct.pack('!BBI', DHCP_IP_LEASE_TIME, 4, self.lease_time)  # Lease Time
        packet += struct.pack('!BBI', DHCP_SUBNET_MASK, 4, self.ip_to_int('255.255.255.0'))  # Subnet Mask
        packet += struct.pack('!BBI', DHCP_ROUTER, 4, siaddr)  # Router (Gateway)
        packet += struct.pack('!BBI', DHCP_DNS, 4, siaddr)  # DNS Server
        packet += struct.pack('!B', DHCP_END)  # End option
        
        return packet
    
    def create_dhcp_ack(self, xid, mac_address, yiaddr):
        """Create a DHCP ACK packet"""
        # Header fields
        op = 2  # Boot Reply
        htype = 1  # Ethernet
        hlen = 6  # MAC address length
        hops = 0
        secs = 0
        flags = 0x8000  # Broadcast flag set
        ciaddr = 0  # Client IP address
        siaddr = self.ip_to_int(self.server_ip)  # Server IP address
        giaddr = 0  # Gateway IP address
        
        # Fill chaddr field with MAC and padding
        chaddr = mac_address + bytes([0] * (16 - len(mac_address)))  # Ensure it's 16 bytes
        
        # Server host name and Boot file name (empty)
        sname = bytes([0] * 64)
        file = bytes([0] * 128)
        
        # Create the basic packet structure
        packet = struct.pack('!BBBBIHH', op, htype, hlen, hops, xid, secs, flags)
        packet += struct.pack('!II', ciaddr, yiaddr)
        packet += struct.pack('!II', siaddr, giaddr)
        packet += chaddr
        packet += sname
        packet += file
        
        # Add DHCP magic cookie
        packet += DHCP_MAGIC_COOKIE
        
        # Add DHCP options
        packet += struct.pack('!BBB', DHCP_MESSAGE_TYPE, 1, DHCP_ACK)  # Message Type: ACK
        packet += struct.pack('!BBI', DHCP_SERVER_ID, 4, siaddr)  # Server Identifier
        packet += struct.pack('!BBI', DHCP_IP_LEASE_TIME, 4, self.lease_time)  # Lease Time
        packet += struct.pack('!BBI', DHCP_SUBNET_MASK, 4, self.ip_to_int('255.255.255.0'))  # Subnet Mask
        packet += struct.pack('!BBI', DHCP_ROUTER, 4, siaddr)  # Router (Gateway)
        packet += struct.pack('!BBI', DHCP_DNS, 4, siaddr)  # DNS Server
        packet += struct.pack('!B', DHCP_END)  # End option
        
        return packet
    
    def parse_dhcp_packet(self, data):
        """Parse a DHCP packet"""
        if len(data) < 240:  # Minimum DHCP packet size
            self.logger.warning(f"Packet too small: {len(data)} bytes")
            return None
        
        try:
            # Parse header
            op = data[0]
            htype = data[1]
            hlen = data[2]
            hops = data[3]
            xid = struct.unpack('!I', data[4:8])[0]
            secs = struct.unpack('!H', data[8:10])[0]
            flags = struct.unpack('!H', data[10:12])[0]
            ciaddr = struct.unpack('!I', data[12:16])[0]
            yiaddr = struct.unpack('!I', data[16:20])[0]
            siaddr = struct.unpack('!I', data[20:24])[0]
            giaddr = struct.unpack('!I', data[24:28])[0]
            chaddr = data[28:28+hlen]  # Use hlen to get MAC address
            
            # Find DHCP magic cookie
            if data[236:240] != DHCP_MAGIC_COOKIE:
                self.logger.warning("Invalid DHCP packet: Magic cookie mismatch")
                return None
            
            # Parse options
            options = {}
            i = 240
            while i < len(data):
                if data[i] == DHCP_END:
                    break
                if data[i] == 0:  # Padding
                    i += 1
                    continue
                
                if i + 1 >= len(data):
                    break
                
                option = data[i]
                length = data[i+1]
                
                if i + 2 + length > len(data):
                    break
                
                value = data[i+2:i+2+length]
                options[option] = value
                i += 2 + length
            
            # Get DHCP message type
            message_type = None
            if DHCP_MESSAGE_TYPE in options and len(options[DHCP_MESSAGE_TYPE]) == 1:
                message_type = options[DHCP_MESSAGE_TYPE][0]
            
            return {
                'op': op,
                'xid': xid,
                'chaddr': chaddr,
                'message_type': message_type,
                'options': options
            }
        except Exception as e:
            self.logger.error(f"Error parsing DHCP packet: {e}")
            return None
    
    def lease_monitor(self):
        """Thread function to monitor and release expired leases"""
        while True:
            self.release_expired_leases()
            time.sleep(5)  # Check every 5 seconds
    
    def run(self):
        """Run the DHCP server"""
        # Start lease monitoring thread
        lease_thread = threading.Thread(target=self.lease_monitor, daemon=True)
        lease_thread.start()
        
        self.logger.info("Waiting for DHCP requests...")
        
        try:
            while True:
                try:
                    data, addr = self.sock.recvfrom(1024)
                    packet = self.parse_dhcp_packet(data)
                    
                    if not packet:
                        continue
                    
                    mac_address = packet['chaddr']
                    mac_str = ':'.join(f'{b:02x}' for b in mac_address)
                    xid = packet['xid']
                    
                    if packet['message_type'] == DHCP_DISCOVER:
                        self.logger.info(f"Received DHCPDISCOVER from {mac_str}")
                        
                        # Allocate IP address
                        allocated_ip = self.allocate_ip(mac_address)
                        if not allocated_ip:
                            self.logger.warning(f"Cannot allocate IP for {mac_str}, IP pool exhausted")
                            continue
                        
                        # Create and send DHCPOFFER
                        offer_packet = self.create_dhcp_offer(xid, mac_address, allocated_ip)
                        self.sock.sendto(offer_packet, ('255.255.255.255', 68))
                        self.logger.info(f"Sent DHCPOFFER with IP {self.int_to_ip(allocated_ip)} to {mac_str}")
                    
                    elif packet['message_type'] == DHCP_REQUEST:
                        self.logger.info(f"Received DHCPREQUEST from {mac_str}")
                        
                        # Find the allocated IP
                        mac_key = binascii.hexlify(mac_address).decode()
                        if mac_key in self.allocated_ips:
                            allocated_ip, _ = self.allocated_ips[mac_key]
                            
                            # Create and send DHCPACK
                            ack_packet = self.create_dhcp_ack(xid, mac_address, allocated_ip)
                            self.sock.sendto(ack_packet, ('255.255.255.255', 68))
                            self.logger.info(f"Sent DHCPACK with IP {self.int_to_ip(allocated_ip)} to {mac_str}")
                        else:
                            self.logger.warning(f"Received DHCPREQUEST from unknown client {mac_str}")
                except Exception as e:
                    self.logger.error(f"Error processing packet: {e}")
        
        except KeyboardInterrupt:
            self.logger.info("DHCP Server shutting down...")
        finally:
            self.sock.close()


if __name__ == "__main__":
    server = DHCPServer()
    server.run()
