
def noop(*args, **kw):
	pass

from .logging import LoggerMixin
	
Base = LoggerMixin
	
NOT_SET = object()

DEFAULT_ENCODING = "utf-8"
BASE_STR = unicode

def uc(s):
	if isinstance(s, unicode):
		return s
	if isinstance(s, basestring):
		return s.decode(DEFAULT_ENCODING)
	return unicode(s)
	
def tostr(o):
	if isinstance(o, basestring):
		return o
	return BASE_STR(o)

def identity(x):
	return x