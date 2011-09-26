'''
Created on 22.07.2011

@author: kca
'''
from AbstractController import AbstractController
from django.http import Http404
from django.conf.urls.defaults import patterns

class ReflectiveController(AbstractController):
	def _handle_request(self, request, method, *args):
		if method.startswith("_"):
			raise Http404()
		
		try:
			f = getattr(self, method.replace("-", "_"))
		except AttributeError:
			raise Http404()
		
		return f(request, *args)

class Controller(ReflectiveController):
	@property
	def urlpatterns(self):
		return patterns(r'^%s/(.+?)/(.*)$' % (self.name, ), self)
	
		