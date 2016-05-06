# THIS IS NOT A DEFAULT SETUP FILE!!!!
#this is to be used when generating binary executable
#note that you will need to copy the pyasn1 folder (from pyasn1 installation) to the site-packages folder!!!!

from distutils.core import setup
import py2exe

setup( options = {'py2exe': {'bundle_files': 1, 'compressed': True}},
       console=['kerberoastv2.py'],
	   zipfile = None, 
	  )
