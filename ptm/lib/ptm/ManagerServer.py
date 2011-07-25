#! /usr/bin/env python

from Manager import Manager
try:
	from ManagerAdapter import ManagerAdapter
except ImportError:
	ManagerAdapter = None
from wsgiref import simple_server
from wsgi import ManagerWSGIXMLRPCRequestHandler, ThreadingWSGIServer

class BasicManagerWSGIApplication(ManagerWSGIXMLRPCRequestHandler):
	def __init__(self, manager, encoding):
		ManagerWSGIXMLRPCRequestHandler.__init__(self, encoding = encoding)
		self.__manager = manager
		self.register_instance(self.manager.get_method_dispatcher())

	def get_manager(self):
		return self.__manager
	manager = property(get_manager)
		
class ManagerWSGIApplication(BasicManagerWSGIApplication):
	def __init__(self, manager_url, registry_url = None, encoding = None):
		manager = Manager(manager_url = manager_url, registry_url = registry_url)
		BasicManagerWSGIApplication.__init__(self, manager, encoding);

class BasicManagerServer(object):
	def __init__(self, application, bind_address = None, port = None, *args, **kw):
		super(BasicManagerServer, self).__init__(*args, **kw)
		
		if bind_address is None:
			bind_address = "0.0.0.0"
		
		if port is None:
			port = 8081
		else:
			port = int(port)
			
		self.__application = application
		self.__server = simple_server.make_server(bind_address, port, application, server_class = ThreadingWSGIServer)
		
	def serve_forever(self):
		self.__server.serve_forever()
		
	def get_manager(self):
		return self.__application.manager
	manager = property(get_manager)

class ManagerServer(BasicManagerServer):
	def __init__(self, parent, bind_address = None, port = None, registry_url = None, xenadapter = False, nodeadapter = False, packageadapter = False, networkingadapter = False, systemuseradapter = False, *args, **kw):		
		if registry_url == None:
			registry_url = "http://ptmregistry:8000"

		if bind_address is None:
			bind_address = "0.0.0.0"

		myaddress = bind_address
		if bind_address == "0.0.0.0":
			import socket
		
			hostname = socket.getfqdn()
			myaddress = socket.gethostbyname(hostname)
			if myaddress == "127.0.0.1":
				myaddress = hostname
				
		if port is None:
			port = 8081
		else:
			port = int(port)

		myaddress = "http://%s:%d" % (myaddress, port)
		application = ManagerWSGIApplication(myaddress, registry_url)
		manager = application.manager

		if nodeadapter:
			from NodeAdapter.NodeAdapter import NodeAdapter
			NodeAdapter(manager = manager)

		if networkingadapter:
			from NetworkingAdapter.NetworkingAdapter import NetworkingAdapter
			NetworkingAdapter(manager = manager, parent = parent)

		if systemuseradapter:
			from SystemUserAdapter.SystemUserAdapter import SystemUserAdapter
			SystemUserAdapter(manager = manager, parent = parent)

		if xenadapter:
			from XenAdapter import XenAdapter
			XenAdapter(parent = parent, manager = manager)

		if packageadapter:
			from PackageAdapter.PackageAdapter import SoftwareAdapter
			SoftwareAdapter(manager = manager, parent = parent, engine = "sqlite:////var/lib/ptm/SoftwareAdapter.sqlite")
		
		if ManagerAdapter is None:
			import logging
			logger = logging.getLogger("ptm")
			logger.warn("Could not import ManagerAdapter. Running without one.")
			del logger
		else:
			ManagerAdapter(manager = manager, parent = parent)
		
		super(ManagerServer, self).__init__(application = application, bind_address = bind_address, port = port, *args, **kw)


		
		
