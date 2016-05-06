from PyADhack.ad_ldap import *


def parse_info(ldap_record):
	temp = dict()
	temp['pwdLastSet']        = long_to_dateime(ldap_record['pwdLastSet'][0])
	temp['sAMAccountName']    = ldap_record['sAMAccountName'][0]
	temp['userPrincipalName'] = ldap_record.get('userPrincipalName',['',''])[0]
	temp['lastLogon']         = long_to_dateime(ldap_record.get('lastLogon',['0','0'])[0])
	temp['whenCreated']       = long_to_dateime(ldap_record.get('whenCreated',['0','0'])[0])
	temp['servicePrincipalName'] = list()
	for t in ldap_record['servicePrincipalName']:
		temp['servicePrincipalName'].append(t)
		
	return temp

def getSPNaccounts(url, base, user, password):
	l = AD_LDAP( url, base, user, password)
	l.connect()

	entries = list()
	
	#print 'Enumerating service users'

	for resultList in l.get_all_service_account():
		for entry, result in resultList:
			if entry is None:
				continue
			if entry.lower().find('watchdog') != -1:
				continue
			try:
				entries.append(parse_info(result))
			except Exception as e:
				print 'err data: ' + str(result)
				print 'Exception : ' + str(e)
	
	return entries

if __name__ == '__main__':
	from getpass import getpass
	import json

	output_filename = ''

	url      = '' # needs format "ldap://server_ip:port" could be ldaps
	user     = '' #needs format DOMAIN\\user 
	password = getpass()
	base     = '' #needs format "dc=<COMPANY>,dc=corp"
	
	
	accounts = getSPNaccounts(url, base, user, password)
	
			
	print 'Successfully enumerated' + str(len(accounts)) + 'users'
	
	print 'Writing results to file...'
	
	with open(output_filename,'wb') as f:
		json.dump(accounts,f, default=json_serial)
			
	print 'Done!'
