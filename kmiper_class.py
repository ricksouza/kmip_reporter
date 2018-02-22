from kkmip import ttv
from kkmip import types
from xml.etree import ElementTree
from xml.dom import minidom
import socket
import ssl


class Kmiper():

	address = None
	port = None
	keyfile = None
	certfile = None
	socket = None
	name = None

	def __init__(self, address, port, keyfile, certfile, name):
		self.address = address
		self.port = port
		self.keyfile = keyfile
		self.certfile = certfile
		self.name = name
		self.create_socket()
		
	def create_socket(self):
		"""
		From PyKmip
		"""
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		
		sock = ssl.wrap_socket(
		sock,
		keyfile = self.keyfile,
		certfile = self.certfile,
            ssl_version=ssl.PROTOCOL_TLSv1_2
            )
		sock.settimeout(900)
		self.sock = sock
		
	def connect(self):
		"""
		From PyKmip
		"""
		try:
			self.sock.connect((self.address, self.port))
			return True 
		except Exception as e:
			print("An error occurred while connecting to host: " + self.address+":"+self.port)
			self.sock.close()
			print(e)
			return False
			
	def disconnect(self):
		"""
		From PyKmip
		"""
		if self.sock:
			try:
				self.sock.shutdown(socket.SHUT_RDWR)
				self.sock.close()
			except OSError:
				# Can be thrown if the socket is not actually connected to
				# anything. In this case, ignore the error. (from PyKmip)
				pass
		
	#Write and Read

	def write(self, byte_string):
		sbuffer = bytes(byte_string)
		self.sock.sendall(sbuffer)

	def read(self):
		read_block_size = 4096
		total_msg = b''
		# while 1:
		msg = self.sock.recv(read_block_size)
		# if not msg:
		# 	break
		total_msg += msg
		return total_msg

	def send_receive(self, byte_string):
		self.write(byte_string)
		return self.read()

	def parse_ttlv_bytes_to_xml_tree(self, ttlv):
		ttv_tree = ttv.ttlv.decode(ttlv)
		xml = ttv.xml.encode(ttv_tree)
		return xml

	def parse_ttlv_bytes_to_xml_string(self, ttlv):
		return ttv.xml.encode_to_string(self.parse_ttlv_bytes_to_xml_tree(ttlv)).decode("utf-8") 

	def parse_ttlv_bytes_to_xml_pretty_string(self, ttlv):
		return parse_xml_string_to_pretty_string(
			ttv.xml.encode_to_string(self.parse_ttlv_bytes_to_xml_tree(ttlv)).decode("utf-8"))

	def parse_ttlv_hex_to_xml_tree(self, ttlv):
		return self.parse_ttlv_bytes_to_xml_tree(bytearray.fromhex(ttlv))

	def parse_ttlv_hex_to_xml_string(self, ttlv):
		return self.parse_ttlv_bytes_to_xml_string(bytearray.fromhex(ttlv))

	def parse_xml_to_ttlv_bytes(self, xml_node):
		ttv_node = ttv.xml.decode(xml_node)
		types_obj = types.encoding.decode(ttv_node)
		new_ttv_node  = types_obj.encode()
		ttlv_obj = new_ttv_node.encode_ttlv()
		return ttlv_obj

	def parse_xml_string_to_ttlv_bytes(self, string):
		return self.parse_xml_to_ttlv_bytes(ElementTree.fromstring(string))

	def parse_xml_string_to_ttlv_hex(self, string):
		return binascii.hexlify(self.parse_xml_to_ttlv_bytes(string))

	def parse_xml_string_to_pretty_string(self, string):
		return minidom.parseString(string).toprettyxml(indent="  ").replace("<?xml version=\"1.0\" ?>\n", "")

	def parse_xml_to_pretty_string(self, xml):
		return self.parse_xml_string_to_pretty_string(ttv.xml.encode_to_string(xml))