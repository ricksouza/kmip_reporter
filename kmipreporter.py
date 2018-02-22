from kmiper.kmiper import *
import sys
import binascii
from datetime import datetime, timedelta



def writeToFile(xmlString, path, filename):
	with open(path + filename, "w") as f:
		f.write(xmlString)
		
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


def parse_xml_otp(xml_node, otp):
	if "otpcode" == xml_node.tag.lower():
		print("found otp to replace: " + otp)
		xml_node.attrib['value'] = otp
	for e in xml_node:
		parse_xml_otp(e, otp)

def parse_signature_data(xml_node, signature):
	if "signaturedata" == xml_node.tag.lower():
		if "SIGNATURE" in xml_node.attrib['value']:
			print("found signature  to replace: " + signature['sign'])
			xml_node.attrib['value'] = signature['sign']
		else:
			signature['sign'] = xml_node.attrib['value']
			print("found signature  to store: " + signature['sign'])
	for e in xml_node:
		parse_signature_data(e, signature)

def parse_xml_timestamp(xml_node):
	if "value" in xml_node.attrib:
		if "$NOW-3600" in xml_node.attrib['value']:
			print("found timestamp to replace: " + (datetime.utcnow() - timedelta(seconds=3600)).isoformat() )
			xml_node.attrib['value'] = (datetime.utcnow() - timedelta(seconds=3600)).isoformat()
		elif "$NOW" in xml_node.attrib['value']:
			print("found timestamp to replace: " + datetime.utcnow().isoformat())
			xml_node.attrib['value'] = datetime.utcnow().isoformat()
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
	
	#Caso seja fornecido pelo menos um argumento (arquivo xml), leia o primeiro argumento como arquivo
	if len(sys.argv) > 1:
		filename = sys.argv[1]
		with open(filename, 'r') as myfile:
			data = myfile.read().replace('\n', '').replace('\t','')
	else:
		data = sys.stdin.read().replace('\n', '').replace('\t','')


	#caso sejam fornecidos 2 argumentos, o segundo será o otp

	otp = ""
	idStore = {}
	idtemplate = "$UNIQUE_IDENTIFIER_"
	if len(sys.argv) >2:
		otp = sys.argv[2]
		print("otp  : " + otp)
		
	#caso sejam fornecidos 3 ou 4 argumentos, são identificadores de chaves (Para que??)

	if len(sys.argv) >3:
		newid = idtemplate+str(len(idStore))
		idStore[newid] = sys.argv[3]

	if len(sys.argv) >4:
		newid = idtemplate+str(len(idStore))
		idStore[newid] = sys.argv[4]


	PATH = "report/"
	sock = create_socket()
	sign = {}

	#if connect(sock, "34.227.71.133", 9002): #Safenet
	if connect(sock, "200.202.33.23", 5696):
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

			#parse req for ID
			print('\033[92m'+parse_xml_to_pretty_string(ereq)+'\033[0m')
			parse_xml_unique_id(ereq, idStore, idtemplate)
			parse_xml_timestamp(ereq)
			parse_signature_data(ereq, sign)
			if len(otp)>0:
				parse_xml_otp(ereq, otp)
			results += parse_xml_to_pretty_string(ereq)
			#print(idStore)

			#Parse xml to TTLV and send to HSM
			ttlv = parse_xml_to_ttlv_bytes(ereq)
			#print(binascii.hexlify(ttlv))
			#print("")
			received = send_receive(sock, ttlv)
			#print(binascii.hexlify(received))
			
			#Parse response to store IDs and append to report
			response = parse_ttlv_bytes_to_xml_tree(received)
			print('\033[94m'+parse_xml_to_pretty_string(response)+'\033[0m')
			
			parse_signature_data(response, sign)
			result_status = parse_xml_result_status(response)
			expec_result_status = parse_xml_result_status(eres)
			print(expec_result_status)
			
			results += parse_xml_to_pretty_string(response)
			results += "\n\\newpage\n"
			
			print(result_status)
			#if(result_status != expec_result_status):
			#	result_msg = parse_xml_result_message(response)
			#	print(result_msg)
			#	break
				
			parse_xml_unique_id(response, idStore, idtemplate)
			parse_xml_unique_id(eres, idStore, idtemplate)
			
		disconnect(sock)
		writeToFile(expectedResults.replace("$", ""), PATH, "expected.tex")
		writeToFile(results, PATH, "results.tex")
	exit()

if __name__ == "__main__":
	main()
