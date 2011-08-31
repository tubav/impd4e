#! /usr/bin/env python
'''
Created on 11.08.2010

@author: kca
'''

from ptm.ManagerServer import BasicManagerWSGIApplication, BasicManagerServer
from PTMHub import PTMHub

class HubWSGIApplication(BasicManagerWSGIApplication):
	def __init__(self, encoding = None, *args, **kw):
		manager = PTMHub()
		BasicManagerWSGIApplication.__init__(self, encoding = encoding, manager = manager, *args, **kw)

class TestHubServer(BasicManagerServer):
	def __init__(self, bind_address = None, port = None, *args, **kw):
		application = HubWSGIApplication()
		if port is None:
			port = 8000
		super(TestHubServer, self).__init__(application = application, bind_address = bind_address, port = port, *args, **kw)
		
from restfrontend import RESTFrontendApplication
		
class HubServerApplication(HubWSGIApplication):	
	def __init__(self, port, prefix = None, tgw_url = None, encoding = None, *args, **kw):
		from HTMLFrontend.HTMLFrontend import HTMLFrontend

		if not prefix:
			prefix = "test"
		
		HubWSGIApplication.__init__(self, encoding = encoding, *args, **kw)
		huburl = "http://localhost:%s" % (port, )
		self.__rest = RESTFrontendApplication(registry_url = huburl, prefix = prefix)
		self.__html = HTMLFrontend(rest_url = huburl + "/rest", webcontext = "/html", prefix = prefix)
		
		if tgw_url:
			from ptmhub.ra.TGWAdapter import TGWAdapter
			TGWAdapter(self.manager, tgw_url, prefix = prefix)

	def __dorest(self, environ, start_response):
		environ["PATH_INFO"] = environ["PATH_INFO"][5:]
		return self.__rest(environ, start_response)  

	def __call__(self, environ, start_response): 
		method = environ["REQUEST_METHOD"]
		path = environ["PATH_INFO"]
		#print("processing request: %s" % (path, ))
		if method == "GET" and ("/.hg/" in path or path.endswith("/favicon.ico")):
			start_response("404 Not found", [("Content-Type", "text/plain"), ])
			return ()
		
		if method not in ("GET", "POST") or path.startswith("/rest"):
			return self.__dorest(environ, start_response)
		
		if path.startswith("/html"):
			environ["PATH_INFO"]= path[5:]
			return self.__html(environ, start_response)
			
		if method == "GET":
			return self.__html(environ, start_response)
			
		return HubWSGIApplication.__call__(self, environ, start_response)
				
		
		
class HubServer(BasicManagerServer):
	def __init__(self, bind_address = None, port = None, prefix = None, tgw_url = None, *args, **kw):
		if port is None:
			port = 8000
		if prefix is None:
			prefix = "test"
		application = HubServerApplication(port = port, prefix = prefix, tgw_url = tgw_url)
		super(HubServer, self).__init__(application = application, bind_address = bind_address, port = port, *args, **kw)

def main():
	import sys
	import logging
	from optparse import OptionParser

	parser = OptionParser()
	parser.add_option("-x", "--prefix", dest="prefix", help="Set prefix for PTM", default="ptmtest")
	parser.add_option("-p", "--port", type="int", dest="port", help="Set port for PTM")
	parser.add_option("-g", "--tgw", dest="tgw_url", help = "URL of the Teagle gateway")
	(options, _args) = parser.parse_args()
	
	logger = logging.getLogger("ptm")
	console = logging.StreamHandler()
	formatter = logging.Formatter('Manager: %(levelname)s [%(funcName)s(%(filename)s:%(lineno)s] - %(message)s')
	console.setFormatter(formatter)
	console.setLevel(logging.DEBUG)
	logger.setLevel(logging.DEBUG)
	logger.addHandler(console)
	
	#raise Exception(options)

	#TestHubServer().serve_forever()
	HubServer("0.0.0.0", options.port, options.prefix, options.tgw_url).serve_forever()
	sys.exit(0)
	
	
if __name__ == "__main__":
	main()