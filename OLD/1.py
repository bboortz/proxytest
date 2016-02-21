#!/usr/bin/env python

import socket
import cherrypy
from urllib2 import urlopen
from contextlib import closing
import json

class GeoLocation(object):

	def __init__(self):
		# Automatically geolocate the connecting IP
		self.url = 'http://freegeoip.net/json/'

	def get_location(self, ip):	
		res = "";
		res = """<h2>Geo Location </h2>""" 
		try:
			with closing(urlopen(self.url)) as response:
				location = json.loads(response.read())
				res += "<ul>"
				for key in location:
					if (key == "ip"): 
						continue
					value = location.get(key, None)
					res += "<li>%s = %s</li>" % (key, value)
				res += "</ul>"
			
		except:
			res += "<b>Cannot determine location.</b>"

		res += "<br />"

		return res



class Root(object):
	def __init__(self):
		self.geolocation = GeoLocation() 


	@cherrypy.expose
	def index(self, *args, **kwargs):
		res = ""

		res += """

<html>
<head>
<script type='text/javascript'>
function jsTests() {
	gatewayTest();
}
function gatewayTest() {
var xhttp = new XMLHttpRequest();
xhttp.open('GET', '/gwtest', true);
xhttp.send();
	alert(xhttp.status);
}
</script>
</head>

<body onload=\"jsTests();\" >"""

		res += self.process_request(cherrypy.request)
		res += self.process_cookies(cherrypy.request.cookie)
		res += self.process_header(cherrypy.request.headers)
		res += self.process_proxy_header(cherrypy.request.headers)
		res += self.geolocation.get_location(self.client_ip)

		self.set_cookies(cherrypy.response.cookie)


		return res + "</body></html>"

	@cherrypy.expose
	def gwtest(self, *args, **kwargs):
		raise cherrypy.TimeoutError()
		cherrypy.response.status = 499
		res = "<h1>Service Unavailable</h1>"
		return res
#		import time
#		cherrypy.request.config.update({'tools.sessions.timeout': 0}) 
#		time.sleep(300)
#		res = "test"


	def process_request(self, request):
		res = ""
		res = """<h2>Request </h2>"""

		remote = request.remote
		client_ip = request.remote.ip
		self.client_ip = client_ip
		client_port = request.remote.port
		client_host = socket.gethostbyaddr(client_ip)[0]
		scheme = request.scheme
		request_line = request.request_line
		method = request.method
		server_protocol = request.server_protocol
		base = request.base
		path = request.path_info
		query_string = request.query_string
		params = request.params

		res += "<ul>"
		res += "<li>Client: %s (%s) : %s</li>" % (client_ip, client_host, client_port)
		res += "<li>Scheme: %s</li>" % scheme
		res += "<li>Request Line: %s</li>" % request_line 
		res += "<li>Method: %s</li>" % method
		res += "<li>Protocol: %s</li>" % server_protocol
		res += "<li>Base: %s</li>" % base
		res += "<li>Path: %s</li>" % path
		res += "<li>Query String: %s</li>" % query_string
		res += "<li>Parameter: %s</li>" % params
		res += "</ul>"
		res += "<br />"

		return res


	def process_cookies(self, cookies):
		res = ""

		res = """<h2>Cookie List (#: %s):</h2>""" % len(cookies)
		res += "<ul>"
		for key in cookies.keys():
			value = cookies.get(key, None)
			res += "<li>%s = %s</li>" % (key, value.value)
		res += "</ul>"
		res += "<br />"

		return res

	
	def set_cookies(self, cookies):
		cookies['cookieName'] = 'cookieValue'
		cookies['cookieName']['path'] = '/'
		cookies['cookieName']['max-age'] = 3600
		cookies['cookieName']['version'] = 1


	def process_header(self, headers):
		res = ""

		encodings = headers.encodings

		res = """<h2>Header List (#: %s):</h2>""" % len(headers)
		res += "<ul>"
		for key in headers.keys():
			value = headers.get(key, None)
			res += "<li>%s = %s</li>" % (key, value)
		res += "<li>Encodings: %s </li>" % encodings
		res += "</ul>"
		res += "<br />"
		
		return res


	def process_proxy_header(self, headers):
		res = ""

		remote_addr = cherrypy.request.headers.get('Remote-Addr', None)
		forwarded = cherrypy.request.headers.get('FORWARDED', None)
		http_forwarded = cherrypy.request.headers.get('HTTP_FORWARDED', None)
		http_x_forwarded_for = cherrypy.request.headers.get('HTTP_X_FORWARDED_FOR', None)
		via = cherrypy.request.headers.get('via', None)
		host = cherrypy.request.headers.get('Host', None)

		res = """<h2>Proxy Header List:</h2>"""
		res += "<ul>"
		res += "<li>Remote-Addr: %s </li>" % remote_addr
		res += "<li>FORWARDED: %s </li>" % forwarded
		res += "<li>HTTP_FORWARDED: %s </li>" % http_forwarded
		res += "<li>HTTP_X_FORWARDED_FOR: %s </li>" % http_x_forwarded_for
		res += "<li>via: %s </li>" % via
		res += "<li>Host: %s </li>" % host
		res += "</ul>"
		res += "<br />"
		
		return res


def show_blank_page_on_error():
    """Instead of showing something useful to developers but
    disturbing to clients we will show a blank page.

    """
    cherrypy.response.status = 500

    cherrypy.response.body = ''


def secureheaders():
    headers = cherrypy.response.headers
    headers['X-Frame-Options'] = 'DENY'
    headers['X-XSS-Protection'] = '1; mode=block'
    headers['Content-Security-Policy'] = "default-src='self'"

# set the priority according to your needs if you are hooking something
# else on the 'before_finalize' hook point.


#def CORS():
#    cherrypy.response.headers["Access-Control-Allow-Origin"] = "*"

if __name__ == '__main__':
	cherrypy.config.update({
		'server.socket_port': 9090,
		'server.socket_host': '0.0.0.0',
		'request.error_response': show_blank_page_on_error,
		'tools.secureheaders.on': True,
		'tools.sessions.on': True,
		'tools.sessions.httponly': True,
	})
#		'tools.CORS.on': True
#		'response.stream': True,

#	cherrypy.tools.CORS = cherrypy.Tool('before_handler', CORS)
	cherrypy.tools.secureheaders = cherrypy.Tool('before_finalize', secureheaders, priority=60)
	cherrypy.quickstart(Root())

