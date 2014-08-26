#!/usr/bin/env python
#
# SysProof - 	Transparently encrypts all incoming emails by using
#		the LDAP server as keystore.
#
# Written by Chema Garcia (aka sch3m4)
#	chema@safetybits.net || http://safetybits.net
#	@sch3m4
#

import sys
import ldap
import gnupg
import syslog
import email
from os.path import expanduser

VERSION = '0.0.1'

SERV = 'ldap://10.0.1.15:389'
USERDN = 'cn=postfix,ou=bind,dc=example,dc=com'
PWD = 'password'
PROTOCOL = ldap.VERSION3

BASEDN = 'ou=users,dc=example,dc=com'
MAIL_FIELD = 'mail'
FILTER = '(&(objectClass=person)(objectClass=SysProof)(mailEnabled=TRUE)(encryptMail=TRUE)(' + MAIL_FIELD + '='
SCOPE = ldap.SCOPE_SUBTREE
FIELDS = [MAIL_FIELD,'encPublicKey','encPKId']

GNUPG_HOME = expanduser('~') + '/.gnupg'

class NoEncryptInformation(Exception): pass

class SysProof:
	def __init__(self,ldapresult):
		list = ldapresult.keys()
		if not 'mail' in list or not 'encPublicKey' in list or not 'encPKId' in list:
			raise NoEncryptInformation

		self.mail = ldapresult['mail'][0]
		self.encPublicKey = ldapresult['encPublicKey'][0]
		self.encPKId = ldapresult['encPKId'][0]
		self.gpg = gnupg.GPG(gnupghome=GNUPG_HOME)
		public_keys = self.gpg.list_keys()
		found = False
		for i in public_keys:
			if i['keyid'] == self.encPKId:
				found = True
				break
		if found is False:
			self.gpg.import_keys(self.encPublicKey)

	def __encrypt__(self,data):
		return self.gpg.encrypt(data,self.encPKId,always_trust=True)


	def encryptMail ( self , mail ):
		if mail.is_multipart() is False:
			syslog.syslog(syslog.LOG_WARNING,"Not encrypting no multipart emails")
			return mail

		bnd = ''
		for part in mail.walk():
		        if type(part.get_payload()) != type(str()):
				bnd = part.get_boundary()
				if 'multipart/encrypted' in part.values() or 'X-SysProof-Version' in part.keys():
					break

				sbj = part['Subject']
				part.replace_header ( 'Subject','[SysProof] ' + sbj )
				part.add_header ( 'X-SysProof-Version' , VERSION )
		                continue

			encrypted = str ( self.__encrypt__ ( part.get_payload() ) )
			part.set_payload ( encrypted )

		mail.preamble = 'This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)'
		mail.preamble += '\n--' + bnd
		mail.preamble += '\nContent-Type: application/pgp-encrypted'
		mail.preamble += '\nContent-Description: PGP/MIME version identification'
		mail.preamble += '\n\nVersion: 1\n'
		mail.set_boundary(bnd)
		mail.epilogue = "SysProof has protected this email of being read internally on server side for a major confidentiality"

		return mail

		
def main( mail , raw ):
	try:
		cnx = ldap.initialize(SERV)
		cnx.protocol_version = PROTOCOL
		cnx.simple_bind(USERDN,PWD)
	except Exception,e:
		print "Error: %s" % e
		return

	try:
		syslog.syslog(syslog.LOG_INFO,"Querying user data: %s" % mail )
		ldap_result_id = cnx.search(BASEDN, SCOPE, FILTER + mail + '))', FIELDS)
		result_type, result_data = cnx.result(ldap_result_id, 0)
		if result_data == []:
			syslog.syslog(syslog.LOG_INFO,"SysProof not enabled for user %s" % mail)
			return

		udata = None
		for i in result_data:
			if i[1]['mail'][0] == mail:
				syslog.syslog(syslog.LOG_INFO,"User %s has SysProof enabled" % mail)
				udata = i[1]
				break

		if udata is None:
			syslog.syslog(syslog.LOG_INFO,"SysProof not enabled for user %s" % mail)
			return
	except ldap.LDAPError, e:
		syslog.syslog(syslog.LOG_INFO,"Error querying LDAP server: %s" % e)
		print e
		return

	try:
		sp = SysProof(udata)
	except Exception,e:
		print "Excepcion: %s" % e
		return

	msg = email.message_from_string ( raw )
	return sp.encryptMail( msg )


if __name__ == "__main__":
	syslog.openlog(ident="SysProof",facility=syslog.LOG_MAIL)
	try:
		mail = sys.argv[1]
	except:
		syslog.syslog(syslog.LOG_WARNING,"A valid destination email address is needed as first parameter")
		sys.exit(-1)

	raw = sys.stdin.read()

	try:
		print main( mail , raw )
	except Exception,e:
		syslog.syslog(syslog.LOG_WARNING,"Error: %s" % e )
		sys.exit(-1)

	sys.exit(0)
