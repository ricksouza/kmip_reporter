from kmiper.kmiper import *
import sys
import binascii
from datetime import datetime, timedelta
from kmiper_class import Kmiper
from xml_runner_class import XML_runner
		

def main():
	"""
	In development! Here be dragons!
	using OASIS profile XML notation, root node is <kmip>
	followed by child pairs <requestmessage> and <responsemessage>
	in this order. Must not change.
	"""
	
	idStore = {}

	hsm_address = "kryptus.dyndns.biz"
	
	keyfile_hsm1 = "kryptus/vHSM_3/user1.key"
	certfile_hsm1 = "kryptus/vHSM_3/user1.crt"
	port_hsm1 = 49172
	
	hsm_address2 = "200.202.33.23"
	keyfile_hsm2 = "dinamo/rsa2k_iti.pem"
	certfile_hsm2 = "dinamo/rsa2k_cert_iti.pem"
	port_hsm2 = 5696
	
	#Kryptus2 ->  port_hsm2 = 49192
	
	hsm1 = Kmiper(hsm_address, port_hsm1, keyfile_hsm1, certfile_hsm1, "#######   HSM 1  ########")
	hsm2 = Kmiper(hsm_address2, port_hsm2, keyfile_hsm2, certfile_hsm2, "#######   HSM 2  ########")
	
	#HSM1 - Importer
	
	if(hsm1.connect() != True):
		exit()
		
	file_export_pub_key_hsm1 = "testcases/ktc/ktc_export_public_key_hsm1.xml"
	xml1 = XML_runner(hsm1, file_export_pub_key_hsm1, idStore)
	xml1.init_test()
	
	#HSM2 - Exporter
	
	if(hsm2.connect() != True):
		exit()
		
	file_export_keys_hsm2 = "testcases/ktc/ktc_export_keys_hsm2_password.xml"
	xml2 = XML_runner(hsm2, file_export_keys_hsm2, idStore)
	xml2.init_test()
	
	#HSM1 - Importer
	
	file_imported_exported_keys_hsm1 = "testcases/ktc/ktc_import_exported_keys_hsm1.xml"
	xml3 = XML_runner(hsm1, file_imported_exported_keys_hsm1, idStore)
	xml3.init_test()
	
	#CleanUp
	file_cleanup_hsm1 = "testcases/ktc/ktc_clean_up_hsm1.xml"
	xml4 = XML_runner(hsm1, file_cleanup_hsm1, idStore)
	xml4.init_test()
	
	file_cleanup_hsm2 = "testcases/ktc/ktc_clean_up_hsm2_password.xml"
	xml5 = XML_runner(hsm2, file_cleanup_hsm2, idStore)
	xml5.init_test()

	#Disconnecting
	hsm1.disconnect()
	hsm2.disconnect()
	
	exit()
	
if __name__ == "__main__":
	main()
