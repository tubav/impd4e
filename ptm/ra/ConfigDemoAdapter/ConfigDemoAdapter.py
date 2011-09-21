'''
Created on 13.08.2010

@author: kca
'''

from ptm.ResourceAdapter import AbstractResourceAdapter
from ptm import Identifier
from ptm.exc import DuplicateNameError, ConfigurationAttributeError, InstanceNotFound
import logging

logger = logging.getLogger("ptm")

class ConfigDemoAdapter(AbstractResourceAdapter):
	'''
	classdocs
	'''


	def __init__(self, manager, *args, **kw):
		super(ConfigDemoAdapter, self).__init__(*args, **kw)
		self.__instances = { "paul": {"hometown": "berlin", "age": 31, "height": 5.8} }
		manager.register_adapter("/person", self)
		logger.debug("---up---")
		
	def list_resources(self, parent, typename):
		return [ Identifier("/person-" + i) for i in self.__instances ]

	def add_resource(self, parent_id, name, typename, config, owner = None):
		assert(typename == "person")
		
		if not name:
			i = 0
			while True:
				n = str(i)
				if n not in self.__instances:
					break
				i += 1
			name = n
		else:
			if name in self.__instances:
				raise DuplicateNameError(parent_id, typename, name)
		
		self.__instances.add(n)
		
		return name

	def get_resource(self, identifier):
		return identifier

	def have_resource(self, identifier):
		assert(identifier.parent == None)
		assert(identifier.typename == "person")
		return identifier.name in self.__instances

	def get_configuration(self, identifier):
		assert(identifier.parent == None)
		assert(identifier.typename == "person")
		
		try:
			return self.__instances
		except KeyError:
			raise InstanceNotFound(identifier)

	def set_configuration(self, identifier, config):
		assert(identifier.parent == None)
		assert(identifier.typename == "person")
		
		if not self.have_resource(identifier):
			raise InstanceNotFound(identifier)
		
		self.__instances[identifier.resourcename] = config

	def get_attribute(self, identifier, name):
		assert(identifier.parent == None)
		assert(identifier.typename == "person")

		try:
			instance = self.__instances[identifier.resourcename]
		except KeyError:
			raise InstanceNotFound(identifier)
		
		try:
			return instance[name]
		except KeyError:
			raise ConfigurationAttributeError(name)

	def set_attribute(self, identifier, name, value):
		assert(identifier.parent == None)
		assert(identifier.typename == "person")
		
		try:
			instance = self.__instances[identifier.resourcename]
		except KeyError:
			raise InstanceNotFound(identifier)
		
		if name not in instance:
			raise ConfigurationAttributeError(name)
		
		instance[name] = value

	def delete_resource(self, identifier, owner, force = False):
		assert(identifier.parent == None)
		assert(identifier.typename == "person")
		self.__instances.pop(identifier.resourcename)

