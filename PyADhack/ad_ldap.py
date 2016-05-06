import ldap
from ldap.controls import SimplePagedResultsControl
from datetime import datetime, timedelta
import time

def long_to_dateime(input):
	if input == '':
		return 'N/A'
	if input.find('Z') != -1:
		input = input.split('.')[0]
		return datetime.fromtimestamp(time.mktime(time.strptime(input,'%Y%m%d%H%M%S'))).isoformat()
	try:
		long(input)
	except:
		print input
		return 'N/A'
		pass
	ansiTimeStart = datetime(1601,1,1)
	return (ansiTimeStart + timedelta(seconds=long(input)/10000000)).isoformat()	

class AD_LDAP():
	def __init__(self, url, base, user, password):
		self.url       = url
		self.base      = base
		self.user      = user
		self.password  = password
		self.page_size = 1000             #1000 is the max page size for MS-AD
		self.lcon      = ''

	def connect(self):
		ldap.set_option(ldap.OPT_REFERRALS, 0)
		self.lcon = ldap.initialize(self.url,trace_level=0)
		self.lcon.protocol_version = 3
		self.lcon.simple_bind_s(self.user, self.password)

	def get_all_service_account(self, filter = '*'):
		search_flt = r'(servicePrincipalName='+filter+')'
		searchreq_attrlist=["servicePrincipalName","sAMAccountName",'userPrincipalName',"pwdLastSet","lastLogon","whenCreated"]
		return self.pagedsearch(search_flt, searchreq_attrlist)
		
		
	def pagedsearch(self, search_flt, searchreq_attrlist):
		req_ctrl = SimplePagedResultsControl(True,size=self.page_size,cookie='')
		known_ldap_resp_ctrls = { SimplePagedResultsControl.controlType:SimplePagedResultsControl,}

		# Send search request
		msgid = self.lcon.search_ext( self.base, ldap.SCOPE_SUBTREE, search_flt, attrlist=searchreq_attrlist, serverctrls=[req_ctrl])

		pages = 0
		i = 0

		while True:
			pages += 1
			rtype, rdata, rmsgid, serverctrls = self.lcon.result3(msgid,resp_ctrl_classes=known_ldap_resp_ctrls)

			yield rdata

			pctrls = [c for c in serverctrls if c.controlType == SimplePagedResultsControl.controlType]
			if pctrls:
				if pctrls[0].cookie:
				  # Copy cookie from response control to request control
					req_ctrl.cookie = pctrls[0].cookie
					msgid = self.lcon.search_ext(self.base,ldap.SCOPE_SUBTREE,search_flt,attrlist=searchreq_attrlist,serverctrls=[req_ctrl])
				else:
					break
			else:
				print "Warning: Server ignores RFC 2696 control."
				break