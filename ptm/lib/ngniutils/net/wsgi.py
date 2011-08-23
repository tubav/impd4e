'''
Created on 17.07.2011

@author: kca
'''

from wsgiref.simple_server import WSGIServer
from SocketServer import ThreadingMixIn

class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
	pass