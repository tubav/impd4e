#! /usr/bin/env python

class HTTPError(Exception):
	def __init__(self, code, msg, *args, **kw):
		Exception.__init__(self, int(code), msg, *args, **kw)
	
	@property
	def code(self):
		return self.args[0]
	
	@property
	def msg(self):
		return self.args[1]

from ptm import Identifier
from ptm.t1client.BaseSerializer import BaseSerializer
from ptm.t1client.GlobalIdentifier import GlobalIdentifier

import logging
logger = logging.getLogger("ptm")

class XMLSerializer(BaseSerializer):	
	def __init__(self, client, prefix, *args, **kw):
		super(XMLSerializer, self).__init__(prefix = prefix, *args, **kw)
		self.__client = client

	def _unserialize_reference(self, v):
			#raise Exception(v)
			v = unicode(v)

			logger.debug("unser ref: %s (%s)" % (v, self.prefix))

			if v.startswith("//"):
				ptm_name, sep, id = v[2:].partition("/")
				if not ptm_name:
					raise ValueError("Illegal id: %s" % v)
				if ptm_name == self.ptm_name:
					v = sep + id
				else:
					v = "/ptm-" + ptm_name + sep + id
			elif not v.startswith("/"):
				ps = v.find("./")
				if ps > 0 and ps <= v.find("/") + 1:
					prefix, v = v.split("./", 1)
					if prefix != self.prefix[:-1]:
						v = "/ptm-" + prefix + "/" + v
					else:
						v = "/" + v
			return self.__client.get_resource(v)

from ptm.PTMClient import PTMClient
from ptm.exc import LookupError, NoAdapterFoundError, IdentifierException, InstanceNotFound

class HTTPRequest(object):
	def __init__(self, rfile, headers):
		self.rfile = rfile
		self.headers = headers
		self.__read = 0
		try:
			self.__content_length = int(headers["Content-Length"])
		except:
			self.__content_length = None

	def __read(self, max = None):
		if max is None: 
			if self.__content_length is None:
				r = self.rfile.read()
			max = self.__content_length
		
		if self.__content_length and max > self.__content_length - self.__read:
			max = self.__content_length - self.__read
			if max <= 0:
				raise EOFError()
			r = self.rfile.read(max)

		self.__read += len(r)
		return r

class HTTPReply(object):
	def __init__(self, wfile):
		self.wfile = wfile
		self.__headers = {}

	def send(self, response, headers = {}):
		pass

	def set_header(self, keyword, value):
		self.__headers[keyword] = str(value)

	def send_header(self, keyword, value):
		self.wfile.write("%s: %s\r\n" % (keyword, value))

class RestFrontend(object):
	def __init__(self, registry_url = None, prefix = None, *args, **kw):
		super(RestFrontend, self).__init__(*args, **kw)
		self.__client = PTMClient(registry_url)
		self.__serializer = XMLSerializer(self.__client, prefix)
		self.__prefix = prefix

	def __get_identifier(self, identifier):
		logger.debug("__get_identifier: %s" % (identifier, ))
		if identifier.startswith("/" + self.__prefix + "."):
			identifier = identifier[1:]
		identifier = GlobalIdentifier(identifier, default_prefix = self.__prefix)

		if identifier.prefix != self.__prefix:
			return Identifier("/ptm-" + identifier.prefix) / Identifier(identifier)
	
		return Identifier(identifier)

	def do_GET(self, path, rfile, wfile, headers):
		try:
			identifier = self.__get_identifier(path)
			logger.debug("GET %s" % identifier)
			if identifier.is_adapter:
				resources = self.__client.list_resources(identifier, None)
				logger.debug("ents: " + str(resources))
				return self.__serialize([ Identifier(u.identifier) for u in resources ], wfile)
					
			resource = self.__client.get_resource(identifier)
		except (NoAdapterFoundError, InstanceNotFound),  e:
			raise HTTPError(404, str(e))
		except IdentifierException, e:
			logger.exception("Illegal Identifier: %s" % (path, ))
			raise HTTPError(406, str(e))
		except Exception, e:
			logger.exception("failed to get resource")
			raise HTTPError(500, repr(e))

		self.__serialize(resource, wfile)

	def do_PUT(self, path, rfile, wfile, headers):
		return self.do_POST(path, rfile, wfile, headers)

	def do_POST(self, path, rfile, wfile, headers):
		cl = headers["Content-Length"]

		request = rfile.read(int(cl))
		logger.debug("got request: %s\n%s" % (path, request))

		buffer = StringIO(request)
		try:
			typename, config, action = self.__serializer.unserialize(buffer)
		finally:
			buffer.close()

		config.pop("identifier", None)
		name = config.pop("name", None)
		
		try:
			identifier = path
			identifier = self.__get_identifier(identifier)
			if action:
				logger.debug("UPDATE %s" % identifier)
				e = self.__client.get_resource(identifier)
				e.set_configuration(config)
				return self.__serialize(e, wfile)
			else:
				logger.debug("ADD %s" % identifier)
				logger.debug(typename)
				logger.debug(config)
				e = self.__client.add_resource(identifier, name, typename, config, None)
		except LookupError:
			logger.debug("Failed to resolve: " + identifier)
			raise HTTPError(404)
		except Exception, e:
			logger.exception("error during POST")
			raise HTTPError(500, str(e))
		
		self.__serialize(e, wfile)

	def do_DELETE(self, path, rfile, wfile, headers):
		identifier = self.__get_identifier(path)
		logger.debug("DELETE %s" % identifier)
		
		e = self.__client.get_resource(identifier)
		e.delete()

	def __serialize(self, resource, wfile):
		buffer = StringIO()
		try:
			self.__serializer.serialize(resource, buffer)
			response = buffer.getvalue()
		finally:
			buffer.close()

		logger.debug("writing response:" + response)
		wfile.write(response)
		
import BaseHTTPServer
from BaseHTTPServer import BaseHTTPRequestHandler
import SocketServer
from cStringIO import StringIO

class RESTServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer, RestFrontend):
	class RequestHandler(BaseHTTPRequestHandler):
		def __getattr__(self, a):
			logger.debug("getattr: " + a)
			if not a.startswith("do_"):
				raise AttributeError(a)
			m = getattr(self.server, a)
			def handler():
				wfile = StringIO()
				try:
					logger.debug("Executing")
					m(self.path, self.rfile, wfile, self.headers)
					content = wfile.getvalue()
					self.send_response(200)
					self.send_header("Content-Type", "application/xml")
					self.send_header("Content-Length", str(len(content)))
					self.end_headers()
					self.wfile.write(content)
				except HTTPError, e:
					msg = str(e)
					if not msg:
						msg = None
					self.send_error(e.code, msg)
				except Exception, e:
					logger.exception("Error during request")
					self.send_error(500, str(e))
				finally:
					wfile.close()

			return handler	

	def __init__(self, address, registry_url, prefix):
		BaseHTTPServer.HTTPServer.__init__(self, address, RESTServer.RequestHandler)
		RestFrontend.__init__(self, registry_url, prefix)

class RESTFrontendApplication(RestFrontend):   
	def __call__(self, environ, start_response):
		rfile = environ["wsgi.input"]
		method = environ["REQUEST_METHOD"]
		wfile = StringIO()
		path = environ["PATH_INFO"]
		headers = environ
		if "CONTENT_TYPE" in headers:
			headers["Content-Type"] = headers["CONTENT_TYPE"]
		if "CONTENT_LENGTH" in headers:
			headers["Content-Length"] = headers["CONTENT_LENGTH"]
		
		f = getattr(self, "do_" + method)
		try:
			f(path, rfile, wfile, headers)
			content = wfile.getvalue()
			resp = "200 OK"
			ct = "application/xml"
		except HTTPError, e:
			logger.exception("Error in RESTFrontend: %s" % (e, ))
			resp = "%s %s" % (e.code, e.msg,)
			content = "<html><head><title>%s</title></head><body><h1>%s</h1></body></html>" % (resp, repr(e), )
			ct = "text/html"
		except Exception, e:
			logger.exception("Error in RESTFrontend: %s" % (e, ))
			resp = "500 %s" % (e,)
			content = "<html><head><title>%s</title></head><body><h1>%s</h1></body></html>" % (resp, repr(e), )
			ct = "text/html"
		
		headers = [ ("Content-Type", ct), ("Content-Length", str(len(content))) ]
		logger.debug("Returning response: %s %s %s" % (headers, resp, content))
		start_response(resp, headers)
		return [ content ]
	
def main():
	import sys

	console = logging.StreamHandler()
	formatter = logging.Formatter('REST: %(levelname)s [%(funcName)s(%(filename)s:%(lineno)s] - %(message)s')
	console.setFormatter(formatter)
	console.setLevel(logging.DEBUG)
	logger.setLevel(logging.DEBUG)
	logger.addHandler(console)

	if len(sys.argv) > 1:
		port = int(sys.argv[1])
	else:
		port = 8001

	logger.debug("Starting")
	r = RESTServer(("0.0.0.0", port), "http://127.0.0.1:8000", "test")
	r.serve_forever()
	return 0


if __name__ == "__main__":
	import sys
	sys.exit(main())
