'''
Created on 17.07.2011

@author: kca
'''

from memcache import Client, SERVER_MAX_KEY_LENGTH, SERVER_MAX_VALUE_LENGTH
from ngniutils import Base
from collections import MutableMapping 
import pickle
from logging import DEBUG

class SharedCache(Client, Base, MutableMapping):
	def __init__(self, servers = None, debug = None, pickleProtocol=0,
	                 pickler=pickle.Pickler, unpickler=pickle.Unpickler,
	                 pload=None, pid=None, server_max_key_length=SERVER_MAX_KEY_LENGTH,
	                 server_max_value_length=SERVER_MAX_VALUE_LENGTH):
		if debug is None:
			debug = self.logger.isEnabledFor(DEBUG)
			
		super(SharedCache, self).__init__()
		
	def clear(self):
		self.flush_all()
		
	def __getitem__(self, k):
		v = super(SharedCache, self).get(k)
		if v is None:
			raise KeyError(k)
		return v
