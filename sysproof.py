#!/usr/bin/env python
#
# SysProof -    Encrypts all incoming/outgoing emails by using
#               the parameters stored in the LDAP server.
#
# Written by Chema Garcia (aka sch3m4)
#       chema@safetybits.net || http://safetybits.net
#       @sch3m4
#

import sys
import ldap
import gnupg
import syslog
import email
from os.path import expanduser

VERSION = '0.0.2'

# LDAP connection parameters
SERV = 'ldap://172.16.0.1:389'
USERDN = 'cn=user,ou=bind,dc=domain,dc=tld'
PWD = 'userpassword'
PROTOCOL = ldap.VERSION3

# LDAP search parameters
BASEDN = 'ou=users,dc=domain,dc=tld'
MAIL_FIELD = 'mail'
FILTER = '(&(objectClass=person)(objectClass=SysProof)(mailEnabled=TRUE)(encryptMail=TRUE)(%s=' % MAIL_FIELD
SCOPE = ldap.SCOPE_SUBTREE
FIELDS = [MAIL_FIELD,'encPublicKey','encPKId']

# GPG home
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
                # do we have the the key?
                public_keys = self.gpg.list_keys()
                found = False
                for i in public_keys:
                        if i['keyid'] == self.encPKId:
                                found = True
                                break
                # import the public key
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
                                # ---------------------------------------
                                # message already encrypted
                                # ---------------------------------------
                                if 'multipart/encrypted' in part.values() or 'X-SysProof-Version' in part.keys():
                                        break
                                if 'Subject' in part.keys():
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
        # LDAP connection
        try:
                cnx = ldap.initialize(SERV)
                cnx.protocol_version = PROTOCOL
                cnx.simple_bind(USERDN,PWD)
        except Exception,e:
                print "Error ldap/connect: %s" % e
                return raw

        try:
                syslog.syslog(syslog.LOG_INFO,"Querying user data: %s" % mail )
                ldap_result_id = cnx.search(BASEDN, SCOPE, FILTER + mail + '))', FIELDS)
                result_type, result_data = cnx.result(ldap_result_id, 0)
                # not enough data
                if result_data == []:
                        syslog.syslog(syslog.LOG_INFO,"SysProof not enabled for user %s" % mail)
                        return raw

                udata = None
                for i in result_data:
                        if i[1]['mail'][0] == mail:
                                syslog.syslog(syslog.LOG_INFO,"User %s has SysProof enabled" % mail)
                                udata = i[1]
                                break

                if udata is None:
                        syslog.syslog(syslog.LOG_INFO,"SysProof not enabled for user %s" % mail)
                        return raw
        except ldap.LDAPError, e:
                syslog.syslog(syslog.LOG_INFO,"Error querying LDAP server: %s" % e)
                return raw

        try:
                sp = SysProof(udata)
        except Exception,e:
                syslog.syslog(syslog.LOG_INFO,"Error creating SysProof object: %s" % e)
                return raw

        msg = email.message_from_string ( raw )
        msg = sp.encryptMail( msg )
        syslog.syslog(syslog.LOG_INFO,"Email to %s encryped" % mail )
        return msg


if __name__ == "__main__":
        syslog.openlog(ident="SysProof",facility=syslog.LOG_MAIL)
        try:
                # destination address
                mail = sys.argv[1]

        except:
                syslog.syslog(syslog.LOG_WARNING,"A valid destination email address is needed as first parameter")
                sys.exit(-1)

        # raw email message
        raw = sys.stdin.read()

        try:
                print main( mail , raw )
        except Exception,e:
                syslog.syslog(syslog.LOG_WARNING,"Main error: %s" % e )
                print raw
                sys.exit(-1)

        sys.exit(0)
