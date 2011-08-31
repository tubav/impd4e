'''
Created on 25.07.2011

@author: kca
'''

import sys
from .logging import get_logger

try:
	from lxml import etree as impl
	from lxml.etree import tostring as _ts
	get_logger(__name__).debug("Using lxml etree implementation.")
	def tostring(element, encoding = "utf-8", pretty_print = False):
		return _ts(element, encoding = encoding, pretty_print = pretty_print)
except ImportError:
	get_logger(__name__).warning("lxml library not found, trying builtin xml.etree. Pretty printing will be disabled.")
	from xml.etree import ElementTree as impl
	from xml.etree.ElementTree import tostring as _ts
	def tostring(element, encoding = "utf-8", pretty_print = False):
		return _ts(element, encoding = encoding)
		
sys.modules[__name__ + ".impl"] = impl

