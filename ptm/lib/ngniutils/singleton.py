'''
Created on 23.07.2011

@author: kca
'''

class SingletonType(type):
	__instances = {}
	
	def get_instance(self):
		try:
			i = self.__instances[self]
		except KeyError:
			i = self()
			self.__instances[self] = i
		return i