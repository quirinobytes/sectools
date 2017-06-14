#!/usr/bin/env python 

import shodan
import sys

SHODAN_API_KEY = "R41C0EHUJnpsryTz39xBNOrCNx74aKZ3"

api = shodan.Shodan(SHODAN_API_KEY)



# Wrap the request in a try/ except block to catch errors
try:
        # Search Shodan
        results = api.search(sys.argv[1:])

        # Show the results
        print 'Results found: %s' % results['total']
        for result in results['matches']:
                print 'IP: %s' % result['ip_str']
                print result['data']
                print ''
except shodan.APIError, e:
        print 'Error: %s' % e



