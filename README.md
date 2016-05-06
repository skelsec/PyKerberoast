# PyKerberoast
Implementing Kerberoast attack fully in python

(AFAIK) The original Kerberoast attack was here: https://github.com/nidem/kerberoast


##Why did I reinwent the wheel?
  This attack is not new, in fact there are multiple loose scripts and software all around the web to do a PoC.
  The only problem with those attacks is that they eighter:
   1. need you to use powershell scripts, whcih might be disabled in your environment
   2. Use mimikatz, which will be detected by AV
   3. Use elevated privileges
   4. Rely on .net framework for the TGS ticket generation
   5. And after all the twisted balancing acts, none of the scripts will generate an output that you can use directly in oclHashcat. BUT oclHashcat now has a gpu implementation for this (-m 13100) YAAAAAY

##Why is this project better than the rest?
   1. I wrote it 
   2. This software will not need elevated privileges to work
   3. This software just does what it's supposed to do
   4. You can generate one packed binary file from this with py2exe and go nuts
    
DISCLAIMER: I did not invent this attack vector!

# Prerequisites
This software relies on two main packages:

## IMPACKET (for kerberos magic)
You will need THE LATEST impacket version OTHERWISE IT WILL NOT WORK!!!!
-thank you Impacket guys for accepting my patch-

https://github.com/CoreSecurity/impacket/


## PyADHack (my in-house project)
This is currently bundled within this repo, but it will move to another separate project later (hopefully)

python-ldap   -   https://pypi.python.org/pypi/python-ldap
