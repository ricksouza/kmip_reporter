from kmiper.kmiper import *
import sys
import binascii
import datetime

def parse_xml_timestamp(xml_node):
	if "timestamp" in xml_node.tag.lower():
		if "$NOW" in xml_node.attrib['value']:
			xml_note.attrib['value'] = datetime.datetime.now().isoformat()
	for e in xml_node:
		parse_xml_timestamp(e)


def parse_xml_unique_id(xml_node, uid):
	if 'value' in xml_node.attrib:
		if "UID" in xml_node.attrib['value']:
			print("found UID to replace with: " + uid)
			xml_node.attrib['value'] = uid
	for e in xml_node:
		parse_xml_unique_id(e, uid)

def main():
	"""
	In development! Here be dragons!
	using OASIS profile XML notation, root node is <kmip>
	followed by child pairs <requestmessage> and <responsemessage>
	in this order. Must not change.
	"""
	filename = sys.argv[1]
	with open(filename, 'r') as myfile:
		data = myfile.read().replace('\n', '').replace('\t','')
	uid = sys.argv[2]
	
	sock = create_socket()
	if connect(sock, "34.227.71.133", 9002):
		req = ElementTree.fromstring(data)
		if "kmip" in req.tag.lower():
			req = req[0]

		#parse req for ID
		parse_xml_unique_id(req, uid)
		parse_xml_timestamp(req)
		print('\033[93m'+parse_xml_to_pretty_string(req)+'\033[0m')

		#Parse xml to TTLV and send to HSM
		ttlv = parse_xml_to_ttlv_bytes(req)
		received = send_receive(sock, ttlv)
		print(binascii.hexlify(received))
			
		#Parse response to store IDs and append to report
		response = parse_ttlv_bytes_to_xml_tree(received)
		print('\033[94m'+parse_xml_to_pretty_string(response)+'\033[0m')
			
		disconnect(sock)
	exit()

if __name__ == "__main__":
	main()
