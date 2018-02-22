from kmiper.kmiper import *
import sys
import binascii
import datetime

def writeToFile(xmlString, path, filename):
	with open(path + filename, "w") as f:
		f.write(xmlString)

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
		
def parse_xml_pub_priv_uids(xml_node, pub_uid, priv_uid):
	if 'UniqueIdentifier'in xml_node.tag:
		if 'UNIQUE_IDENTIFIER_0' in xml_node.attrib['value']:
			xml_node.attrib['value'] = priv_uid
		elif 'UNIQUE_IDENTIFIER_1' in xml_node.attrib['value']:
			xml_node.attrib['value'] = pub_uid
	for e in xml_node:
		parse_xml_pub_priv_uids(e, pub_uid, priv_uid)

		
def parse_xml_otp(xml_node, otp):
	if "otpcode" == xml_node.tag.lower():
		print("found otp to replace: " + otp)
		xml_node.attrib['value'] = otp
	for e in xml_node:
		parse_xml_otp(e, otp)

def main():
	"""
	In development! Here be dragons!
	using OASIS profile XML notation, root node is <kmip>
	followed by child pairs <requestmessage> and <responsemessage>
	in this order. Must not change.
	
	List of parameters: 1-testfilename, 2-otp, 3-pub_uid, 4-priv_uid
	Ex command: python3 runner.py testcases/otp/create-key-pair.xml 087271 None None
	"""
	
	filename = None
	otp = None
	pub_uid = None
	priv_uid = None
	
	arg_names = ['file', 'filename', 'otp', 'pub_uid', 'priv_uid']
	parameters = dict(zip(arg_names, sys.argv))
	
	filename = parameters["filename"]	
	otp = parameters["otp"]
	pub_uid = parameters["pub_uid"]
	priv_uid = parameters["priv_uid"]
	
	print(filename)
	print(pub_uid)
	print(priv_uid)
	print(otp)
	
	#filename = sys.argv[1]
	with open(filename, 'r') as myfile:
		data = myfile.read().replace('\n', '').replace('\t','')
	
	#if len(sys.argv) >2:
	#	uid = sys.argv[2]
	sock = create_socket()
	if connect(sock, "kryptus.dyndns.biz", 49172):
		req = ElementTree.fromstring(data)
		if "kmip" in req.tag.lower():
			req = req[0]

		#parse req for ID
		if(pub_uid != None and priv_uid != None):
			parse_xml_pub_priv_uids(req, pub_uid, priv_uid)
		if(otp != None):
			parse_xml_otp(req, otp)
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
