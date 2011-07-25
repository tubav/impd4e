#! /usr/bin/env python

from xml.dom.minidom import parse, parseString, getDOMImplementation

from ptm.Identifier import Identifier
from ptm.PTMClient import PTMClient
from ptm.Registry import Registry
#from HtmlFrontend import HtmlFrontend

class T1Entity(object):
	def __init__(self, identifier, t1client, config = None):
		self.identifier = identifier
		self.__config = config
		self.t1client = t1client

	def get_config(self):
		if self.__config is None:
			self.__config = self.t1client.get_entity(self.identifier).config
		return self.__config
	config = property(get_config)
		
	def get_parent_id(self):
		identifier = Identifier(self.identifier)
		return identifier.parent
	parent_id = property(get_parent_id)
	
	def get_parent_entity(self):
		p_id = self.get_parent_id()
		return T1Entity(p_id, self.t1client, None)
	parent_entity = property(get_parent_entity)

	def update(self, config):
		self.__config = self.t1client.update(self.identifier, config).config

	def delete(self):
		self.t1client.delete(self.identifier)
	delete = property(delete)

