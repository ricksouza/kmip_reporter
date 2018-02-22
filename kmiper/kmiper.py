from kkmip import ttv
from kkmip import types
from xml.etree import ElementTree
from xml.dom import minidom
import socket
import ssl

#Connection

def create_socket():
	"""
	From PyKmip
	"""
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock = ssl.wrap_socket(
		sock,
		#keyfile="kryptus/vHSM_3/user1.key",
		#certfile="kryptus/vHSM_3/user1.crt",
		#keyfile="safenet/user.key",
		#certfile="safenet/user.crt",
		keyfile="dinamo/rsa2k_iti.pem",
		certfile="dinamo/rsa2k_cert_iti.pem",
		#keyfile="kryptus/vHSM_1/vco1.key",
		#certfile="kryptus/vHSM_1/vco1.pem",
        #cert_reqs=ssl.CERT_REQUIRED,
        #ca_certs="safenet/server_safenet.crt",
        #ca_certs="dinamo/htm_tls_cert_FIPS.PEM",
            #ssl_version=ssl.PROTOCOL_TLSv1_2
            ssl_version=ssl.PROTOCOL_TLSv1_2,
            #do_handshake_on_connect=True
            # do_handshake_on_connect=self.do_handshake_on_connect,
            # suppress_ragged_eofs=self.suppress_ragged_eofs)
            )
	sock.settimeout(900)
	return sock	

def connect(sock, host, port):
	"""
	From PyKmip
	"""
	try:
		sock.connect((host, port))
		return True 
	except Exception as e:
		print("An error occurred while connecting to host: " + host+":"+ str(port))
		sock.close()
		print(e)
		return False

def disconnect(sock):
	"""
	From PyKmip
	"""
	if sock:
		try:
			sock.shutdown(socket.SHUT_RDWR)
			sock.close()
		except OSError:
			# Can be thrown if the socket is not actually connected to
			# anything. In this case, ignore the error. (from PyKmip)
			pass


#Write and Read

def write(sock, byte_string):
	sbuffer = bytes(byte_string)
	sock.sendall(sbuffer)

def read(sock):
	read_block_size = 4096
	total_msg = b''
	# while 1:
	msg = sock.recv(read_block_size)
	# if not msg:
	# 	break
	total_msg += msg
	return total_msg

def send_receive(sock, byte_string):
	write(sock, byte_string)
	return read(sock)


"""
Parsing functions
"""

def parse_ttlv_bytes_to_xml_tree(ttlv):
	ttv_tree = ttv.ttlv.decode(ttlv)
	xml = ttv.xml.encode(ttv_tree)
	return xml

def parse_ttlv_bytes_to_xml_string(ttlv):
	return ttv.xml.encode_to_string(parse_ttlv_bytes_to_xml_tree(ttlv)).decode("utf-8") 

def parse_ttlv_bytes_to_xml_pretty_string(ttlv):
	return parse_xml_string_to_pretty_string(
		ttv.xml.encode_to_string(parse_ttlv_bytes_to_xml_tree(ttlv)).decode("utf-8"))

def parse_ttlv_hex_to_xml_tree(ttlv):
	return parse_ttlv_bytes_to_xml_tree(bytearray.fromhex(ttlv))

def parse_ttlv_hex_to_xml_string(ttlv):
	return parse_ttlv_bytes_to_xml_string(bytearray.fromhex(ttlv))

def parse_xml_to_ttlv_bytes(xml_node):
	ttv_node = ttv.xml.decode(xml_node)
	types_obj = types.encoding.decode(ttv_node)
	new_ttv_node  = types_obj.encode()
	ttlv_obj = new_ttv_node.encode_ttlv()
	return ttlv_obj

def parse_xml_string_to_ttlv_bytes(string):
	return parse_xml_to_ttlv_bytes(ElementTree.fromstring(string))

def parse_xml_string_to_ttlv_hex(string):
	return binascii.hexlify(parse_xml_to_ttlv_bytes(string))

def parse_xml_string_to_pretty_string(string):
	return minidom.parseString(string).toprettyxml(indent="  ").replace("<?xml version=\"1.0\" ?>\n", "")

def parse_xml_to_pretty_string(xml):
	return parse_xml_string_to_pretty_string(ttv.xml.encode_to_string(xml))
