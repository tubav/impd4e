#! /usr/bin/env python
'''
Created on 11.08.2010

@author: kca
'''

from ptm.ManagerServer import BasicManagerWSGIApplication, BasicManagerServer
from PTMHub import PTMHub

class HubWSGIApplication(BasicManagerWSGIApplication):
    def __init__(self, encoding = None, *args, **kw):
        manager = PTMHub()
        BasicManagerWSGIApplication.__init__(self, encoding = encoding, manager = manager, *args, **kw)

class TestHubServer(BasicManagerServer):
    def __init__(self, bind_address = None, port = None, *args, **kw):
        application = HubWSGIApplication()
        if port is None:
            port = 8000
        super(TestHubServer, self).__init__(application = application, bind_address = bind_address, port = port, *args, **kw)
        
from restfrontend import RESTFrontendApplication
        
class HubServerApplication(HubWSGIApplication):    
    def __init__(self, port, encoding = None, *args, **kw):
        from HTMLFrontend.HTMLFrontend import HTMLFrontend
        
        HubWSGIApplication.__init__(self, encoding = encoding, *args, **kw)
        self.__rest = RESTFrontendApplication()
        self.__html = HTMLFrontend("http://localhost:%d/rest" % (port, ), webcontext = "/html")
           
    def __dorest(self, environ, start_response):
        environ["PATH_INFO"] = environ["PATH_INFO"][5:]
        return self.__rest(environ, start_response)  
           
    def __call__(self, environ, start_response): 
        method = environ["REQUEST_METHOD"]
        path = environ["PATH_INFO"]
        print("processing request: %s" % (path, ))
        if method not in ("GET", "POST") or path.startswith("/rest"):
            return self.__dorest(environ, start_response)
        
        if path.startswith("/html"):
            environ["PATH_INFO"]= path[5:]
            return self.__html(environ, start_response)
       
        if method == "GET":
            return self.__html(environ, start_response)
            
        return HubWSGIApplication.__call__(self, environ, start_response)
                
        
        
class HubServer(BasicManagerServer):
    def __init__(self, bind_address = None, port = None, *args, **kw):
        if port is None:
            port = 8000
        application = HubServerApplication(port = port)
        super(HubServer, self).__init__(application = application, bind_address = bind_address, port = port, *args, **kw)


def main():
    import sys
    import logging
    
    logger = logging.getLogger("ptm")
    console = logging.StreamHandler()
    formatter = logging.Formatter('Manager: %(levelname)s [%(funcName)s(%(filename)s:%(lineno)s] - %(message)s')
    console.setFormatter(formatter)
    console.setLevel(logging.DEBUG)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(console)

    #TestHubServer().serve_forever()
    HubServer().serve_forever()
    sys.exit(0)
    
    
if __name__ == "__main__":
    main()