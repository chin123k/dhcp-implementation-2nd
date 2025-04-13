"""
DHCP Client Implementation using Raw Sockets

Features:
- Creates and sends DHCPDISCOVER packet (broadcast on 255.255.255.255:67)
- Receives DHCPOFFER response from server
- Random MAC address generation
- Random transaction ID generation
- Struct packing for packet creation
- Timeout handling (5 seconds waiting for offer)
- Extracts offered IP from server's response
- Logs all events in terminal
- Uses raw UDP socket on port 68 (client port)
"""

import socket
import struct
import random
import logging

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
DHCP_END = 255

# DHCP Magic Cookie
DHCP_MAGIC_COOKIE = bytes([0x63, 0x82, 0x53, 0x63])

class DHCPClient:
    def __init__(self, interface='eth0'):
        self.logger = logging.getLogger('DHCPClient')
        self.interface = interface
        
        # Generate random MAC address
        self.mac_address = self.generate_mac()
        self.mac_str = ':'.join(f'{b:02x}' for b in self.mac_address)
        self.logger.info(f"Using MAC address: {self.mac_str}")
        
        # Generate random transaction ID
        self.xid = random.randint(0, 0xFFFFFFFF)
        self.logger.info(f"Using transaction ID: 0x{self.xid:08x}")
        
        # Create the socket
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.sock.bind(('0.0.0.0', 68))
            self.sock.settimeout(5)  # 5 second timeout
        except Exception as e:
            self.logger.error(f"Failed to create socket: {e}")
            raise
    
    def generate_mac(self):
        """Generate a random MAC address"""
        mac = [random.randint(0, 255) for _ in range(6)]
        mac[0] = mac[0] & 0xFE  # Clear multicast bit
        mac[0] = mac[0] | 0x02  # Set local bit
        return bytes(mac)
    
    def create_dhcp_discover(self):
        """Create a DHCP DISCOVER packet"""
        # Header fields
        op = 1  # Boot Request
        htype = 1  # Ethernet
        hlen = 6  # MAC address length
        hops = 0
        secs = 0
        flags = 0x8000  # Broadcast flag set
        ciaddr = 0  # Client IP address
        yiaddr = 0  # Your IP address
        siaddr = 0  # Server IP address
        giaddr = 0  # Gateway IP address
        
        # Fill chaddr field with MAC and padding
        chaddr = self.mac_address + bytes([0] * (16 - len(self.mac_address)))  # Ensure it's 16 bytes
        
        # Server host name and Boot file name (empty)
        sname = bytes([0] * 64)
        file = bytes([0] * 128)
        
        # Create the basic packet structure
        packet = struct.pack('!BBBBIHH', op, htype, hlen, hops, self.xid, secs, flags)
        packet += struct.pack('!II', ciaddr, yiaddr)
        packet += struct.pack('!II', siaddr, giaddr)
        packet += chaddr
        packet += sname
        packet += file
        
        # Add DHCP magic cookie
        packet += DHCP_MAGIC_COOKIE
        
        # Add DHCP options
        packet += struct.pack('!BBB', DHCP_MESSAGE_TYPE, 1, DHCP_DISCOVER)  # Message Type: DISCOVER
        packet += struct.pack('!B', DHCP_END)  # End option
        
        return packet
    
    def create_dhcp_request(self, offered_ip, server_ip):
        """Create a DHCP REQUEST packet"""
        # Header fields
        op = 1  # Boot Request
        htype = 1  # Ethernet
        hlen = 6  # MAC address length
        hops = 0
        secs = 0
        flags = 0x8000  # Broadcast flag set
        ciaddr = 0  # Client IP address
        yiaddr = 0  # Your IP address
        siaddr = 0  # Server IP address
        giaddr = 0  # Gateway IP address
        
        # Fill chaddr field with MAC and padding
        chaddr = self.mac_address + bytes([0] * (16 - len(self.mac_address)))  # Ensure it's 16 bytes
        
        # Server host name and Boot file name (empty)
        sname = bytes([0] * 64)
        file = bytes([0] * 128)
        
        # Create the basic packet structure
        packet = struct.pack('!BBBBIHH', op, htype, hlen, hops, self.xid, secs, flags)
        packet += struct.pack('!II', ciaddr, yiaddr)
        packet += struct.pack('!II', siaddr, giaddr)
        packet += chaddr
        packet += sname
        packet += file
        
        # Add DHCP magic cookie
        packet += DHCP_MAGIC_COOKIE
        
        # Add DHCP options
        packet += struct.pack('!BBB', DHCP_MESSAGE_TYPE, 1, DHCP_REQUEST)  # Message Type: REQUEST
        packet += struct.pack('!BBI', 50, 4, offered_ip)  # Requested IP address
        packet += struct.pack('!BBI', 54, 4, server_ip)  # Server identifier
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
            
            # Check if this packet is for us
            if xid != self.xid:
                return None
            
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
                'yiaddr': yiaddr,  # Offered IP address
                'siaddr': siaddr,  # Server IP address
                'message_type': message_type,
                'options': options
            }
        except Exception as e:
            self.logger.error(f"Error parsing DHCP packet: {e}")
            return None
    
    def get_ip_address(self):
        """Get an IP address from a DHCP server"""
        # Create and send DHCPDISCOVER
        discover_packet = self.create_dhcp_discover()
        self.logger.info("Sending DHCPDISCOVER...")
        self.sock.sendto(discover_packet, ('255.255.255.255', 67))
        
        # Wait for DHCPOFFER
        try:
            while True:
                data, addr = self.sock.recvfrom(1024)
                packet = self.parse_dhcp_packet(data)
                
                if not packet:
                    continue
                
                if packet['message_type'] == DHCP_OFFER:
                    offered_ip = packet['yiaddr']
                    server_ip = packet['siaddr']
                    offered_ip_str = socket.inet_ntoa(struct.pack('!I', offered_ip))
                    server_ip_str = socket.inet_ntoa(struct.pack('!I', server_ip))
                    self.logger.info(f"Received DHCPOFFER: IP {offered_ip_str} from server {server_ip_str}")
                    
                    # Send DHCPREQUEST
                    self.logger.info(f"Sending DHCPREQUEST for IP {offered_ip_str}...")
                    request_packet = self.create_dhcp_request(offered_ip, server_ip)
                    self.sock.sendto(request_packet, ('255.255.255.255', 67))
                    
                    # Wait for DHCPACK
                    while True:
                        data, addr = self.sock.recvfrom(1024)
                        packet = self.parse_dhcp_packet(data)
                        
                        if not packet:
                            continue
                        
                        if packet['message_type'] == DHCP_ACK:
                            ack_ip_str = socket.inet_ntoa(struct.pack('!I', packet['yiaddr']))
                            self.logger.info(f"Received DHCPACK: IP {ack_ip_str} confirmed")
                            return ack_ip_str
        
        except socket.timeout:
            self.logger.error("Timeout waiting for DHCP response")
            return None
        finally:
            self.sock.close()


if __name__ == "__main__":
    client = DHCPClient()
    ip = client.get_ip_address()
    if ip:
        print(f"Acquired IP address: {ip}")
    else:
        print("Failed to acquire IP address")
