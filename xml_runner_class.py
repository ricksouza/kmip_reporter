from kmiper.kmiper import *
import sys
import binascii
from datetime import datetime, timedelta
from kmiper_class import Kmiper
from enum import Enum

class TipoMSG(Enum):
		REQUEST = 1
		RESPONSE = 2
		
class XML_runner():

	hsm = None
	xmlfile = None
	idStore = {}
	
	def __init__(self, hsm, xmlfile, idStore):
	
		self.hsm = hsm
		self.xmlfile = xmlfile
		self.idStore = idStore
		
	def writeToFile(self, xmlString, path, filename):
		with open(path + filename, "a") as f:
			f.write(xmlString)
		
	def parse_xml_timestamp(self, xml_node):
		if "value" in xml_node.attrib:
			if "$NOW-3600" in xml_node.attrib['value']:
				print("found timestamp to replace: " + (datetime.utcnow() - timedelta(seconds=3600)).isoformat() )
				xml_node.attrib['value'] = (datetime.utcnow() - timedelta(seconds=3600)).isoformat()
			elif "$NOW" in xml_node.attrib['value']:
				print("found timestamp to replace: " + datetime.utcnow().isoformat())
				xml_node.attrib['value'] = datetime.utcnow().isoformat()
		for e in xml_node:
			self.parse_xml_timestamp(e)

			
	def parse_tag(self, xml_node, idStore, tipoMsg, tag, value):
		if tag in xml_node.tag.lower():
			if tipoMsg == TipoMSG.REQUEST:
				if "keyvalue" in tag:
					if 'value' in xml_node.attrib:
						xml_node.attrib['value'] = idStore[xml_node.attrib['value']]
				else:
					if xml_node.attrib['value'] in idStore:
						xml_node.attrib['value'] = idStore[xml_node.attrib['value']]
					else:
						xml_node.attrib['value'] = xml_node.attrib['value']
			else:
				if "keyvalue" in tag:
					if 'value' in xml_node.attrib:
						if value in xml_node.attrib['value']:
							idStore[xml_node.tag] = xml_node.attrib['value']
						else:
							uid_str = idStore[xml_node.tag]
							idStore[uid_str] = xml_node.attrib['value']
				else:			
					if value in xml_node.attrib['value']:
						idStore[xml_node.tag] = xml_node.attrib['value']
					else:
						uid_str = idStore[xml_node.tag]
						idStore[uid_str] = xml_node.attrib['value']
		for e in xml_node:
			self.parse_tag(e, idStore, tipoMsg, tag, value)
	
	def parse_uid(self, xml_node, idStore, tipoMsg):
		self.parse_tag(xml_node, idStore, tipoMsg, "uniqueid", "UID")
			
	def parse_modulus(self, xml_node, idStore, tipoMsg):
		self.parse_tag(xml_node, idStore, tipoMsg, "modulus", "MODULUS")
					
	def parse_pub_exponent(self, xml_node, idStore, tipoMsg):
		self.parse_tag(xml_node, idStore, tipoMsg, "publicexponent", "EXPONENT")
					
	def parse_key_value(self, xml_node, idStore, tipoMsg):
		self.parse_tag(xml_node, idStore, tipoMsg, "keyvalue", "VALUE")
		
	def parse_iv_value(self, xml_node, idStore, tipoMsg):
		self.parse_tag(xml_node, idStore, tipoMsg, "ivcounternonce", "IV")
					
		
	def init_test(self):
	
		PATH = "report/"
	
		with open(self.xmlfile, 'r') as file:
			file_data = file.read().replace('\n', '').replace('\t','')

		expectedResults = ""
		results = ""
		testcase = ElementTree.fromstring(file_data)
		print("################ LEN TEST CASE: " + str(len(testcase)))
		for i in range(0,len(testcase), 2):
		
			ereq = testcase[i]
			eres = testcase[i+1]
			expectedResults += self.hsm.parse_xml_to_pretty_string(ereq)
			expectedResults += self.hsm.parse_xml_to_pretty_string(eres)
			expectedResults += "\n\\newpage\n"
			self.writeToFile(expectedResults.replace("$", ""), PATH, "expected.tex")
			
			self.parse_xml_timestamp(ereq)
			self.parse_uid(ereq, self.idStore, TipoMSG.REQUEST)
			self.parse_modulus(ereq, self.idStore, TipoMSG.REQUEST)
			self.parse_pub_exponent(ereq, self.idStore, TipoMSG.REQUEST)
			self.parse_key_value(ereq, self.idStore, TipoMSG.REQUEST)
			self.parse_iv_value(ereq, self.idStore, TipoMSG.REQUEST)
			
			print(self.hsm.name)
			print('\033[92m'+self.hsm.parse_xml_to_pretty_string(ereq)+'\033[0m')
			
			#Parse xml to TTLV and send to HSM
			ttlv = self.hsm.parse_xml_to_ttlv_bytes(ereq)
			received = self.hsm.send_receive(ttlv)
			print("1")
			
			#Parse response to store IDs and append to report
			response = self.hsm.parse_ttlv_bytes_to_xml_tree(received)
			print('\033[94m'+self.hsm.parse_xml_to_pretty_string(response)+'\033[0m')
			print("2")
			
			self.parse_uid(eres, self.idStore, TipoMSG.RESPONSE)
			self.parse_uid(response, self.idStore, TipoMSG.RESPONSE)
			self.parse_xml_timestamp(response)
			print("3")
			self.parse_modulus(eres, self.idStore, TipoMSG.RESPONSE)
			self.parse_modulus(response, self.idStore, TipoMSG.RESPONSE)
			print("4")
			
			self.parse_pub_exponent(eres, self.idStore, TipoMSG.RESPONSE)
			self.parse_pub_exponent(response, self.idStore, TipoMSG.RESPONSE)
			
			print("5")
			
			self.parse_key_value(eres, self.idStore, TipoMSG.RESPONSE)
			self.parse_key_value(response, self.idStore, TipoMSG.RESPONSE)
			print("6")
			
			self.parse_iv_value(eres, self.idStore, TipoMSG.RESPONSE)
			self.parse_iv_value(response, self.idStore, TipoMSG.RESPONSE)
			print("7")
			results += self.hsm.parse_xml_to_pretty_string(ereq)
			results += self.hsm.parse_xml_to_pretty_string(response)
			#results += "\n\\newpage\n"
			print("8")
			
			self.writeToFile(results, PATH, "results.tex")