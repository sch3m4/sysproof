SysProof
========

A tool to encrypt all incoming emails to dovecot by using GnuPG using LDAP as keystore

Required software
=================
In order to use SysProof you need dovecot to be able to execute external programs as if they were internal plugins. To do that, you need to install the "pigeonhole" sieve:

<dl><pre>
$ apt-get install autoconf2.13 libtool mercurial dovecot-dev dovecot-sieve gnupg python-ldap python-gnupg python-passlib python-crypto
$ hg clone http://hg.rename-it.nl/pigeonhole-0.3-sieve-extprograms
$ cd pigeonhole*
$ ./autogen.sh
$ ./configure --prefix=/usr --with-dovecot=/usr/lib/dovecot --with-pigeonhole=/usr/include/dovecot/sieve --with-moduledir=/usr/lib/dovecot/modules
$ make
$ make install
$ mkdir /etc/dovecot/scripts
$ mkdir /etc/dovecot/sieve-filters/
</pre></dl>

Dovecot configuration
=====================

In order to use dovecot sieves you need to edit /etc/dovecot/conf.d/90-plugin.conf as follows:

<dl><pre>
plugin {
  sieve_plugins = sieve_extprograms
  sieve_global_extensions = +vnd.dovecot.filter
  sieve_filter_bin_dir = /etc/dovecot/sieve-filters
  sieve_before = /etc/dovecot/scripts/.sieve
  sieve_global_dir =/etc/dovecot/scripts
  sieve=/etc/dovecot/scripts/.sieve
}
</pre></dl>

Next, edit /etc/dovecot/scripts/.sieve to use SysProof each time an email arrives:

<dl><pre>
require ["variables", "envelope", "fileinto", "vnd.dovecot.filter"];
if envelope :matches "to" "*" {
        set :lower "my_recipient" "${1}";
        filter "sysproof" "${my_recipient}";
        fileinto "INBOX";
}
</pre></dl>

Set the correct owner and permissions to the scripts and filters folders:

<dl><pre>chown -R vmail:vmail /etc/dovecot/scripts/
chown -R vmail:vmail /etc/dovecot/sieve-filters
</pre></dl>

Install SysProof
================
Afterwards download and install SysProof and all the required software:

<dl><pre>
$ cd /opt
$ git clone https://github.com/sch3m4/sysproof.git sysproof
$ chmod 0755 /opt/sysproof/sysproof.py
$ ln -s /etc/dovecot/sieve-filters/sysproof /opt/sysproof/sysproof.py 
</pre></dl>

Finally, add the sysproof.schema to your LDAP, add "encPublicKey","encryptMail=TRUE" and "encPKId" to the users on the LDAP who you want to encrypt their emails.
