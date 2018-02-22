from kmiper.kmiper import *
import sys
import binascii
import datetime

def writeToFile(xmlString, path, filename):
	with open(path + filename, "w") as f:
		f.write(xmlString)
		
def parse_xml_keys_names(xml_node, priv_key_name, pub_key_name):
	if ("NameValue" == xml_node.tag):
		if(xml_node.attrib['value'] == "PrivKeyName"):
			xml_node.attrib['value'] = priv_key_name
		else:
			xml_node.attrib['value'] = pub_key_name
	for e  in xml_node:
		parse_xml_keys_names(e, priv_key_name, pub_key_name)

def parse_xml_timestamp(xml_node):
	if "timestamp" in xml_node.tag.lower():
		if "$NOW" in xml_node.attrib['value']:
			xml_node.attrib['value'] = datetime.datetime.now().isoformat()
	elif "AttributeValue" in xml_node.tag:
		if (len(xml_node.attrib) > 0):
			if "$NOW" in xml_node.attrib['value']:
				xml_node.attrib['value'] = datetime.datetime.now().isoformat()
	for e in xml_node:
		parse_xml_timestamp(e)
		
def parse_xml_datetime(xml_node):
	if "AttributeValue" in xml_node.tag:
		if "$NOW" in xml_node.attrib['value']:
			xml_node.attrib['value'] = datetime.datetime.now().isoformat()
	for e in xml_node:
		parse_xml_datetime(e)

def parse_xml_result_status(xml_node):
	attrib_value = None
	if ("resultstatus" == xml_node.tag.lower()):
		return xml_node.attrib['value']
	for e in xml_node:
		attrib_value = parse_xml_result_status(e)
		if("resultstatus"== e.tag.lower()):
			return attrib_value
	return attrib_value
	
def parse_xml_result_message(xml_node):
	attrib_value = None
	if ("resultmessage" == xml_node.tag.lower()):
		return xml_node.attrib['value']
	for e in xml_node:
		attrib_value = parse_xml_result_message(e)
		if("resultmessage"== e.tag.lower()):
			return attrib_value
	return attrib_value

def parse_xml_unique_id(xml_node, uid):
	if 'value' in xml_node.attrib:
		if "UID" in xml_node.attrib['value']:
			print("found UID to replace with: " + uid)
			xml_node.attrib['value'] = uid
	for e in xml_node:
		parse_xml_unique_id(e, uid)
		
def parse_req_xml_pub_priv_uids(xml_node, idStore, pub_uid, priv_uid):
	if 'UniqueIdentifier'in xml_node.tag:
		if 'UNIQUE_IDENTIFIER_0' in xml_node.attrib['value']:
			idStore[xml_node.attrib['value']] = priv_uid
			xml_node.attrib['value'] = priv_uid
		elif 'UNIQUE_IDENTIFIER_1' in xml_node.attrib['value']:
			idStore[xml_node.attrib['value']] = pub_uid
			xml_node.attrib['value'] = pub_uid
	for e in xml_node:
		parse_req_xml_pub_priv_uids(e, idStore, pub_uid, priv_uid)
		
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
	idStore = {}
	
	arg_names = ['file', 'filename', 'otp']
	parameters = dict(zip(arg_names, sys.argv))
	
	filename = parameters["filename"]	
	otp = parameters["otp"]
	PATH = "report/"
	
	priv_key_name = "AKLC-M-1-13-private"
	pub_key_name = "AKLC-M-1-13-public"
	
	print(filename)
	print(otp)
	
	#filename = sys.argv[1]
	with open(filename, 'r') as myfile:
		data = myfile.read().replace('\n', '').replace('\t','')
	
	#if len(sys.argv) >2:
	#	uid = sys.argv[2]
	
	sock = create_socket()
	if connect(sock, "kryptus.dyndns.biz", 49192):
	
		expectedResults = ""
		results = ""
		testcase = ElementTree.fromstring(data)
		for i in range(0,len(testcase), 2):
			# Get XML request and expected response.
			ereq = testcase[i]
			eres = testcase[i+1]
			expectedResults += parse_xml_to_pretty_string(ereq)
			expectedResults += parse_xml_to_pretty_string(eres)
			expectedResults += "\n\\newpage\n"
			# Append expected req and resp to string for report
			
			if(otp != None):
				parse_xml_otp(ereq, otp)
			parse_xml_timestamp(ereq)
			#parse_xml_datetime(ereq)
			parse_xml_keys_names(ereq, priv_key_name, pub_key_name)
			
			print('\033[93m'+parse_xml_to_pretty_string(ereq)+'\033[0m')
			
			ttlv = parse_xml_to_ttlv_bytes(ereq)
			received = send_receive(sock, ttlv)
			
			#Parse response to store IDs and append to report
			response = parse_ttlv_bytes_to_xml_tree(received)
			print('\033[94m'+parse_xml_to_pretty_string(response)+'\033[0m')
			
			result_status = parse_xml_result_status(response)
			expec_result_status = parse_xml_result_status(eres)
			
			results += parse_xml_to_pretty_string(ereq)
			results += parse_xml_to_pretty_string(response)
			results += "\n\\newpage\n"
			
			print(result_status)
			if(result_status != expec_result_status):
				result_msg = parse_xml_result_message(response)
				print(result_msg)
				break
			
			
		disconnect(sock)
		writeToFile(expectedResults.replace("$", ""), PATH, "expected.tex")
		writeToFile(results, PATH, "results.tex")
	exit()

if __name__ == "__main__":
	main()
