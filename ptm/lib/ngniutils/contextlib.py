'''
Created on 14.07.2011

@author: kca
'''

class closing(object):
	def __init__(self, o, *args, **kw):
		super(closing, self).__init__(*args, **kw)
		self.__o = o

	def __getattr__(self, k):
		return getattr(self.__o, k)

	def __enter__(self):
		return self.__o

	def __exit__(self, exc_type, exc_val, exc_tb):
		self.__o.close()

	def close(self):
		self.__o.close()
		