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

	favicon_ico = None

	def __init__(self):
		self.geolocation = GeoLocation() 


	@cherrypy.expose
	def index(self, *args, **kwargs):
		res = ""

		# only get requests
		if cherrypy.request.method != 'GET':
			raise cherrypy.HTTPError(404)

		# block requests with expect
		expect = cherrypy.request.headers.get('Expect', None)
		if expect != None:
			raise cherrypy.HTTPError(417)

		# block javascript in requests
		query_string = cherrypy.request.query_string
		if query_string != None and query_string != "":
			print query_string
			if '<script>' in query_string or \
				'</script>' in query_string or \
				'%3Cscript%3E' in query_string or \
				'%3C/script%3E' in query_string:
				raise cherrypy.HTTPError(403)


		# process the request
		res += self.process_request(cherrypy.request)
		res += self.process_cookies(cherrypy.request.cookie)
		res += self.process_header(cherrypy.request.headers)
		res += self.process_proxy_header(cherrypy.request.headers)
		res += self.geolocation.get_location(self.client_ip)

		# set a cookie
		self.set_cookies(cherrypy.response.cookie)

		return res + "</body></html>"


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


def error_page_handler(status, message, traceback, version):
    return "HTTP ERROR %s" % status


def secureheaders():
	headers = cherrypy.response.headers
	headers['X-Frame-Options'] = 'DENY'
	headers['X-XSS-Protection'] = '1; mode=block'
	headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'"
	headers['Server'] = "ProxyTest"


def httponly():
	h = cherrypy.response.header_list
	for i in range(len(h)):
		k, v = h[i]
		if k == 'Set-Cookie':
			h[i] = (k, v + '; HttpOnly')


if __name__ == '__main__':
	cherrypy.config.update({
		'server.socket_port': 9090,
		'server.socket_host': '0.0.0.0',
		'request.error_response': show_blank_page_on_error,
		'error_page.default': error_page_handler,
		'tools.secureheaders.on': True,
		'tools.httponly_cookies.on': True,
		'tools.sessions.on': True,
		'tools.sessions.httponly': True,
	})

	cherrypy.tools.secureheaders = cherrypy.Tool('before_finalize', secureheaders, priority=60)
	cherrypy.tools.httponly_cookies = cherrypy.Tool('on_end_resource', httponly)
	cherrypy.tree.mount(Root(), '/', config = { 
		'/': {
		},
		'/favicon.ico' : { 
			'tools.staticfile.on': False 
			
		}
	})
	cherrypy.engine.start();
	cherrypy.engine.block();

