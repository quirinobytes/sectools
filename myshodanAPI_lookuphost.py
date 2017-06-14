#!/usr/bin/env python 

import shodan
import sys

SHODAN_API_KEY = "R41C0EHUJnpsryTz39xBNOrCNx74aKZ3"

api = shodan.Shodan(SHODAN_API_KEY)



# Wrap the request in a try/ except block to catch errors
try:

   # Lookup the host
   host = api.host(sys.argv[1])

   # Print general info
   print """
	   IP: %s
	   Organization: %s
	   Operating System: %s
   """ % (host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a'))

   # Print all banners
   for item in host['data']:
	   print """
		   Port: %s
		   Banner: %s

	   """ % (item['port'], item['data'])

except shodan.APIError, e:
        print 'Error: %s' % e



