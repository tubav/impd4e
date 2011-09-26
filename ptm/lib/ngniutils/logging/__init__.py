'''
Created on 15.07.2011

@author: kca
'''
from types import ClassType

def get_logger(loggername = None):
	import logging
	logging.basicConfig(level=logging.DEBUG)
	if loggername:
		if not isinstance(loggername, basestring):
			if not isinstance(loggername, (type, ClassType)):
				klass = loggername.__class__ 
			loggername = klass.__module__ + "." + klass.__name__
	else:
		loggername = __name__
		
	try:
		logger = logging.getLogger(loggername)
	except Exception, e:
		print ("Failed to get logger '%s': %s" % (loggername, e))
		raise

	logger.setLevel(logging.DEBUG)
	return logger
	
class LoggerMixin(object):
	@property
	def logger(self):
		try:
			return self.__logger
		except AttributeError:
			self.__logger = get_logger(self)
			return self.__logger
