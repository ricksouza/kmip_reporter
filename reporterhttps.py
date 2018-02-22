import http.client
from kmiper.kmiper import *
import sys
import binascii
import datetime

def connecthttps(url, port):
	return http.client.HTTPSConnection(url, port=port)

def send_receive_https(conn, xml):
	conn.request("POST", "/kmip", data=xml)
	return conn.getresponse()

def writeToFile(xmlString, path, filename):
	with open(path + filename, "w") as f:
		f.write(xmlString)

def parse_xml_otp(xml_node, otp):
	if "otpcode" in xml_node.tag.lowe():
		if "@OTP" in xml_node.attrib['value']:
			print("found otp to replace: " + otp)
			xml_node.attrib['value'] = otp
	for e in xml_node:
		parse_xml_timestamp(e)

def parse_xml_timestamp(xml_node):
	if "value" in xml_node.attrib:
		if "$NOW" in xml_node.attrib['value']:
			print("found timestamp to replace: " + datetime.datetime.utcnow().isoformat())
			xml_node.attrib['value'] = datetime.datetime.utcnow().isoformat()
	for e in xml_node:
		parse_xml_timestamp(e)


def parse_xml_unique_id(xml_node, idStore, idtemplate):
	if "uniqueid" in xml_node.tag.lower():
		if "UNIQUE_ID" in xml_node.attrib['value']:
			print("found UID to replace: " + xml_node.attrib['value'] + "->" + idStore[xml_node.attrib['value']])
			xml_node.attrib['value'] = idStore[xml_node.attrib['value']]
		else:
			newid = idtemplate+str(len(idStore))
			if newid not in idStore.values(): #Por algum motivo não funciona esse if.. sempre passa como true
				idStore[newid] = xml_node.attrib['value']
				print("found id to store: " + newid + " = " +  xml_node.attrib['value'])
	for e in xml_node:
		parse_xml_unique_id(e, idStore, idtemplate)

def main():
	"""
	In development! Here be dragons!
	using OASIS profile XML notation, root node is <kmip>
	followed by child pairs <requestmessage> and <responsemessage>
	in this order. Must not change.
	"""
	if len(sys.argv) > 1:
		filename = sys.argv[1]
		with open(filename, 'r') as myfile:
			data = myfile.read().replace('\n', '').replace('\t','')
	else:
		data = sys.stdin.read().replace('\n', '').replace('\t','')

	otp = ""
	if len(sys.argv) == 3:
		otp = sys.argv[2]
		print("otp  : " + otp)
		print


	PATH = "report/"
	idtemplate = "$UNIQUE_IDENTIFIER_"
	sock = create_socket()

	conn= connecthttps("https://kryptus.dyndns.biz", 49193)
	expectedResults = ""
	results = ""
	testcase = ElementTree.fromstring(data)
	idStore = {}
	for i in range(0,len(testcase), 2):
		# Get XML request and expected response.
		ereq = testcase[i]
		eres = testcase[i+1]
		expectedResults += parse_xml_to_pretty_string(ereq)
		expectedResults += parse_xml_to_pretty_string(eres)
		expectedResults += "\n\\newpage\n"
		# Append expected req and resp to string for report

		#parse req for ID
		print('\033[92m'+parse_xml_to_pretty_string(ereq)+'\033[0m')
		parse_xml_unique_id(ereq, idStore, idtemplate)
		parse_xml_timestamp(ereq)
		if len(otp) > 0:
			parse_xml_otp(ereq, otp)
		results += parse_xml_to_pretty_string(ereq)
		print(idStore)

		#Parse xml to TTLV and send to HSM
		send = parse_xml_to_pretty_string(ereq)
		received = send_receive_https(conn, send)
		
		#Parse response to store IDs and append to report
		response = ElementTree.fromstring(received)
		print('\033[94m'+parse_xml_to_pretty_string(response)+'\033[0m')
		parse_xml_unique_id(response, idStore, idtemplate)
		parse_xml_unique_id(eres, idStore, idtemplate)
		results += parse_xml_to_pretty_string(response)
		results += "\n\\newpage\n"
		
		print(idStore)
		disconnect(sock)
		writeToFile(expectedResults.replace("$", ""), PATH, "expected.tex")
		writeToFile(results, PATH, "results.tex")
	exit()

if __name__ == "__main__":
	main()