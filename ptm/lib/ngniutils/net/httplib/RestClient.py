'''
Created on 21.07.2011

@author: kca
'''

from ngniutils import Base
from urlparse import urlparse
from datetime import datetime
from httplib import HTTPConnection
from ..httplib import HTTPResponseWrapper
from ngniutils.contextlib import closing
from cStringIO import StringIO
from exc import HTTPError, NetworkError


class CachingHttplibResponseWrapper(Base):
	def __init__(self, response, path, tag, last_modified, cache, *args, **kw):
		super(CachingHttplibResponseWrapper, self).__init__(*args, **kw)
		self.__cache = cache
		self.__buffer = StringIO()
		self.__path = path
		self.__tag = tag
		self.__response = response
		self.__last_modified = last_modified
	
	def read(self, n = None):
		s = self.__response.read(n)
		self.__buffer.write(s)
		return s
	
	def readline(self):
		s = self.__response.readline()
		self.__buffer.write(s)
		return s
	
	def readlines(self, sizehint = None):
		lines = self.__response.readlines(sizehint)
		self.__buffer.write(''.join(lines))
		return lines
	
	def close(self):
		if not self.__response.isclosed():
			try:
				self.__buffer.write(self.__response.read())
				self.logger.debug("Putting to cache: %s -> %s, %s\n %s" % (self.__path, self.__tag, self.__last_modified, self.__buffer.getvalue()))
				self.__cache[self.__path] = (self.__tag, self.__last_modified, self.__buffer.getvalue())
			except:
				self.logger.exception("Finalizing response failed")
			finally:
				self.__response.close()
				
		self.__buffer.close()


class RestClient(Base):
	ERROR_RESPONSE_MAX = 320
	
	def __init__(self, uri, username = None, password = None, content_type = "text/plain", headers = None, cache = True, keepalive = True, *args, **kw):			 
		super(RestClient, self).__init__(*args, **kw)

		if cache is True:
			from ngniutils.caching import LRUCache
			cache = LRUCache()
		elif cache == False:
			cache = None
		self.__cache = cache
		self.__uri = uri
		self.__content_type = content_type
		
		info = urlparse(uri)
		
		if info.scheme and info.scheme != "http":
			raise NotImplementedError(info.scheme)
		
		self.__host = info.hostname
		self.__port = info.port and int(info.port) or 80
		self.__base = info.path and info.path.rstrip("/") or ""

		if not headers:
			headers = {}
			
		headers.setdefault("Accept", "*/*")
		headers["Accept-Encoding"] = "identity" #TODO: support compression
		
		if keepalive:
			headers.setdefault("Connection", "Keep-Alive")
		
		if not username:
			username = info.username
		if username:
			if not password:
				password = info.password or ""
			import base64
			headers["Authorization"] = "Basic " + base64.b64encode("%s:%s" % (username, password))
			
		self.__headers = headers
		
	def _get_connection(self):
		return HTTPConnection(self.__host, self.__port)
			
	def request(self, method, path, data = None, headers = None):
		if not path.startswith("/"):
			path = "/" + path   
		fullpath = self.__base + path
		request_headers = self.__headers

		if self.__cache is not None and method == "GET":
			try:
				etag, modified, cached = self.__cache[fullpath]
				if etag:
					request_headers["If-None-Match"] = etag
				request_headers["If-Modified-Since"] = modified
			except KeyError:
				pass
		else:
			request_headers["Content-Type"] = self.__content_type
		
		if headers:
			request_headers.update(headers)
		
		self.logger.debug("%s: %s (%s)" % (method, fullpath, request_headers))
		if method != "GET":
			self.logger.debug(data)
		
		connection = self._get_connection()
		try:
			connection.request(method, fullpath, data, request_headers)
			response = connection.getresponse()
		except Exception, e:
			self.logger.exception("Error during request")
			connection.close()
			if not str(e) or str(e) == "''":
				e = repr(e)
			raise NetworkError("An error occurred while contacting %s:%s: %s. Request was: %s %s" % (self.__host, self.__port, e, method, fullpath))
		
		self.logger.debug("%s %s result: %s" % (method, fullpath, response.status, ))
		if response.status == 304:
			try:
				self.logger.debug("Using cached answer for %s (%s, %s):\n %s" % (fullpath, etag, modified, cached))
				return closing(StringIO(cached))
			except NameError:
				raise NetworkError("Error: %s:%s returned 304 though no cached version is available. Request was: %s %s" % (self.__host, self.__port, e, method, fullpath))
		if response.status >= 300 and response.status < 400:
			raise NotImplementedError("HTTP redirect %s" % (response.status, ))
		if response.status < 200 or response.status >= 300:
			try:
				data = response.read(self.ERROR_RESPONSE_MAX and self.ERROR_RESPONSE_MAX + 1 or None)
				if not data:
					data = "<no further information available>"
				elif self.ERROR_RESPONSE_MAX and len(data) > self.ERROR_RESPONSE_MAX:
					data  = data[:self.ERROR_RESPONSE_MAX] + " (truncated)"  
			except Exception, e:
				data = "<failed to read error response: %s>" % (e, )
			finally:
				response.close()
				connection.close()
			msg = "Error during execution. %s:%s said: %d %s - %s. Request was: %s %s" % (self.__host, self.__port, response.status, response.reason, data, method, fullpath)
			self.logger.exception(msg)
			raise HTTPError(msg = msg, status = response.status, reason = response.reason)  
		
		if method == "DELETE":
			self.__cache.pop(fullpath, None)
		else:
			etag = response.getheader("Etag")
			modified = response.getheader("Last-Modified")
			if etag or modified:
				if not modified:
					modified = datetime.utcnow().strftime("%a, %d %b %Y %X GMT")
				response = CachingHttplibResponseWrapper(response, fullpath, etag, modified, self.__cache)

		return HTTPResponseWrapper(connection, response)

	def get(self, path, headers = None):
		return self.request("GET", path, headers = headers)

	def post(self, path, data, headers = None):
		return self.request("POST", path, data, headers)
	add = post

	def put(self, path, payload, headers = None):
		return self.request("PUT", path, payload)
	update = put
		
	def delete(self, path, headers = None):
		self.request("DELETE", path, None, headers)
