#! /usr/bin/env python



class HTTPError(Exception):
    def __init__(self, code, *args, **kw):
        Exception.__init__(self, *args, **kw)
        self.code = code

from xml.dom.minidom import getDOMImplementation, parseString, Element
from ptm import Resource
from ptm import Identifier

import logging
logger = logging.getLogger("ptm")

class BaseSerializer(object):
    dom_implementation = getDOMImplementation()

    def __init__(self, prefix, *args, **kw):
        super(BaseSerializer, self).__init__(*args, **kw)
        
        if not prefix:
            logger.warn("No prefix given for RestFrontend. Using 'test'")
            prefix = "test"
        elif "/" in prefix:
            raise ValueError("Illegal prefix: %s" % prefix)
        self.__prefix = "//" + prefix

    def get_prefix(self):
        return self.__prefix
    prefix = property(get_prefix)

    def get_ptm_name(self):
        return self.prefix[2:]
    ptm_name = property(get_ptm_name)

    def unserialize(self, rfile):
        if hasattr(rfile, "read"):
            req = rfile.read()
        else:
            req = rfile

        logger.debug("Request: " + req)

        doc = parseString(req)
        return self._unserialize_doc(doc)

    def __find_config_elem(self, root):
            for e in root.childNodes:
                if isinstance(e, Element):
                    if e.tagName.lower() == 'configuration':
                        return e

            return root

    def _unserialize_doc(self, doc):
        try:
            root = doc.documentElement
            typename = root.tagName
            action = root.getAttribute("action")

            root = self.__find_config_elem(root)
            if root != doc.documentElement:
                root = self.__find_config_elem(root)

            config = dict()
            for e in root.childNodes:
                if isinstance(e, Element):
                    config[str(e.tagName).replace("__", "_")] = self.__unserialize(e)
            return typename, config, action
        finally:
            doc.unlink()


    def __unserialize(self, element, need_type = None):
#            raise Exception("Malformed input: " + str(element))

        type = None
        if element.hasAttribute("type"):
            type = element.getAttribute("type").lower()
            if type.endswith("array"):
                if type == "array" or type == "object-array":
                    type = None
                else:
                    type = type.rsplit("-", 1)[0]

                return [ self.__unserialize(e, type) for e in element.childNodes if isinstance(e, Element) ]

        if need_type is not None and type != need_type:
            if type is not None:
                raise TypeError("Wrong type on attribute: %s. need %s" % (type, need_type))
            type = need_type    

        child = element.firstChild
        if child is None:
            return None

        return self._unserialize_value(type, child.data)

    def _unserialize_value(self, type, v):
        if type == "object":
            return None
        if type == "boolean":
            v = unicode(v).lower()
            if v and v[0] in ("1", "t", "y", "j"):
                return True
            return False
        if type == "reference":
            return self._unserialize_reference(v)

        types = {None: unicode, "": unicode, "string": unicode, "float": float, "integer": int}
        try:
            return types[type](v)
        except KeyError:
            raise ValueError("Unknown type: " + str(type))

    def _unserialize_reference(self, id):
        raise NotImplementedError()
    
#    def serialize(self, resource, wfile):
#        doc = self.dom_implementation.createDocument(None, None, None)

#        try:
#            if isinstance(resource, Resource):
#                v = resource
#                identifier = Identifier(resource.getIdentifier())
#                top_element = doc.createElement(identifier.typename)
#                element = doc.createElement("identifier")
#                element.appendChild(doc.createTextNode(unicode(resource.getIdentifier())))
#                element.setAttribute("type", "string")
#                top_element.appendChild(element)
#                for a, value in resource.getConfiguration().iteritems():
##                    value = getattr(resource, a)
#                    top_element.appendChild(self.__serialize(value, doc, a))
#                doc.appendChild(top_element)
#            else:
#                doc.appendChild(self.__serialize(resource, doc))
#
#            doc.writexml(wfile, encoding = "utf-8")
#        finally:
#            doc.unlink()

    def serialize(self, resource, wfile):
        if isinstance(resource, Resource):
#            self.assist_serialize(resource.typename, resource.identifier, resource.get_configuration(), wfile, resource.get_owners())
            self.assist_serialize(resource.typename, resource.identifier, resource.get_configuration(), wfile, {})
        else:
#            raise NotImplementedError()
            
            #TODO: FIXME: WTF: Why is tis here, when do I get here, whats the point?
            doc = self.dom_implementation.createDocument(None, None, None)
            try:
                doc.appendChild(self.__serialize(resource, doc))
                doc.writexml(wfile, encoding = "utf-8")
            finally:
                doc.unlink()
    
    def assist_serialize(self, typename, identifier, config, wfile = None, action = None, owners = None):
        #TODO: FIXME: OMFG
        buf = None
        if wfile is None:
            buf = wfile = StringIO()

        doc = self.dom_implementation.createDocument(None, None, None)
        try:
            # create root node with typename
            root_element = doc.createElement(typename)
            top_element = doc.createElement("configuration")
            root_element.appendChild(top_element)
            if action:
                root_element.setAttribute("action", action)
            # create first child with actual identifier
            if identifier is not None:
                element = doc.createElement("identifier")
                element.appendChild(doc.createTextNode(self.__prefix + unicode(identifier)))
                element.setAttribute("type", "string")
                top_element.appendChild(element)

            for a, value in config.iteritems():
                top_element.appendChild(self.__serialize(value, doc, a))

            if owners is not None:
                owners_element = doc.createElement("owners")
                owners_element.appendChild(self.__serialize(owners, doc, "owners"))
                root_element.appendChild(owners_element)
            
            doc.appendChild(root_element)


            doc.writexml(wfile, encoding = "utf-8")
        finally:
            doc.unlink()

        if buf is not None:
            return buf.getvalue()
    
    def __get_type_attribute(self, v):
        if v is None:
            return "object"
        if isinstance(v, (Resource, Identifier)):
            return "reference"
        if isinstance(v, bool):
            return "boolean"
        if isinstance(v, (int, long)):
            return "integer"
        if isinstance(v, (str, unicode)):
            return "string"
        if isinstance(v, (tuple, set, frozenset, list)):
            return self.__get_array_tag(v) + "-array"
        if isinstance(v, dict):
            return "map"
        raise TypeError("Illegal type: " + str(v.__class__))

    def __get_array_tag(self, v):
        klass = None
        obj = None
        #TODO: rewrite
        for i in v:
            if not isinstance(i, (tuple, set, frozenset, list)):
                newklass = type(i)
                if klass is not None:
                    if not issubclass(newklass, klass):
                        if issubclass(klass, newklass):
                            klass = newklass
                            obj = i
                        else:
                            klass = None
                            obj = None
                            break
                else:
                    klass = newklass
                    obj = i
            else:
                klass = None
                obj = None
                break

        if obj is not None:
            return self.__get_type_attribute(obj)
        return "object"


    def __tag_name(self, v):
        if isinstance(v, (tuple, set, frozenset, list)):
            return "array"
        return v.__class__.__name__

    def __serialize(self, v, doc, tagname = None):
        if tagname is None:
            tagname = self.__get_type_attribute(v)
        else:
            tagname.replace("_", "__")

        top_element = doc.createElement(tagname)
        ta = self.__get_type_attribute(v)
        if ta is not None:
            top_element.setAttribute("type", ta)
        if isinstance(v, (tuple, set, frozenset, list)):
            for i in v:
                top_element.appendChild(self.__serialize(i, doc))
        elif isinstance(v, dict):
            for k, o in v.iteritems():
                ee = doc.createElement("entry")
                ee.appendChild(self.__serialize(k, doc))
                ee.appendChild(self.__serialize(o, doc))
                top_element.appendChild(ee)
        else:
            top_element.appendChild(self._serialize_value(v, doc))

        return top_element

    def _serialize_value(self, v, doc):
        if isinstance(v, Resource):
            v = self.__prefix + unicode(v.identifier)
        if isinstance(v, Identifier):
            v = self.__prefix + unicode(v)
        return doc.createTextNode(unicode(v))

class XMLSerializer(BaseSerializer):    
    def __init__(self, client, prefix, *args, **kw):
        super(XMLSerializer, self).__init__(prefix = prefix, *args, **kw)
        self.__client = client


#        prefix = unicode(prefix)
#        if not prefix.startswith("ptm_"):
#            prefix = "ptm_" + prefix
    def _unserialize_reference(self, v):
            v = unicode(v)

            logger.debug("unser ref: %s" % self.prefix)

            if v.startswith("//"):
                ptm_name, sep, id = v[2:].partition("/")
                if not ptm_name:
                    raise ValueError("Illegal id: %s" % v)
                if ptm_name == self.ptm_name:
                    v = sep + id
                else:
                    v = "/ptm_" + ptm_name + sep + id
            return self.__client.get_resource(v)

from ptm.PTMClient import PTMClient
from ptm.exc import LookupError, NoAdapterFoundError, IdentifierException

class HTTPRequest(object):
    def __init__(self, rfile, headers):
        self.rfile = rfile
        self.headers = headers
        self.__read = 0
        try:
            self.__content_length = int(headers["Content-Length"])
        except:
            self.__content_length = None

    def __read(self, max = None):
        if max is None: 
            if self.__content_length is None:
                r = self.rfile.read()
            max = self.__content_length
        
        if self.__content_length and max > self.__content_length - self.__read:
            max = self.__content_length - self.__read
            if max <= 0:
                raise EOFError()
            r = self.rfile.read(max)

        self.__read += len(r)
        return r

class HTTPReply(object):
    def __init__(self, wfile):
        self.wfile = wfile
        self.__headers = {}

    def send(self, response, headers = {}):
        pass

    def set_header(self, keyword, value):
        self.__headers[keyword] = str(value)

    def send_header(self, keyword, value):
        self.wfile.write("%s: %s\r\n" % (keyword, value))


        

class RestFrontend(object):
    def __init__(self, registry_url = None, prefix = None, *args, **kw):
        super(RestFrontend, self).__init__(*args, **kw)
        self.__client = PTMClient(registry_url)
        self.__serializer = XMLSerializer(self.__client, prefix)
        self.__prefix = prefix

    def __get_identifier(self, identifier):
        #logger.debug("__get_identifier")
        if identifier.startswith("//"):
            name, sep, id = identifier[2:].partition("/")
            if not name:
                raise ValueError("Illegal id: %s" % identifier)
            logger.debug("make ptm resource %s %s" % (name, self.__prefix))
            if name != self.__prefix:
                identifier = "/ptm_" + name + sep + id
            else:
                identifier = sep + id
    
        return Identifier(identifier)
            

    def do_GET(self, path, rfile, wfile, headers):
        
#        identifier = Identifier(path)

        try:
            identifier = self.__get_identifier(path)
            logger.debug("GET %s" % identifier)
            if identifier.is_adapter:
                resources = self.__client.list_resources(identifier, None)
                
                logger.debug("ents: " + str(resources))
                return self.__serialize([ Identifier(u.identifier) for u in resources ], wfile)
                    
            resource = self.__client.get_resource(identifier)
        except NoAdapterFoundError, e:
            raise HTTPError(404, str(e))
        except IdentifierException, e:
            logger.exception("Illegal Identifier: %s" % (identifier, ))
            raise HTTPError(406, str(e))
        except Exception, e:
            logger.exception("failed to get resource")
            raise HTTPError(500, str(e))

        self.__serialize(resource, wfile)

    def do_PUT(self, path, rfile, wfile, headers):
        return self.do_POST(path, rfile, wfile, headers)

    def do_POST(self, path, rfile, wfile, headers):
        #if (path == "/"):
        #    raise HTTPError(501, "Sorry, adding nodes is not yet implemented")
#            raise HTTPError(501)

#        m.register_types()
        logger.debug(headers)
        cl = headers["Content-Length"]

        request = rfile.read(int(cl))
        logger.debug("got request: %s\n%s" % (path, request))


#        identifier = Identifier(path)
        
#        if not identifier.is_manager:
#            logger.debug("Shortcut: %s", identifier)
#            return self.__serialize(self.__client.get_resource(identifier), wfile)

        buffer = StringIO(request)
        try:
            typename, config, action = self.__serializer.unserialize(buffer)
        finally:
            buffer.close()

        config.pop("identifier", None)
        name = config.pop("name", None)
        
        try:
            identifier = self.__get_identifier(path)
            if action:
                logger.debug("UPDATE %s" % identifier)
                e = self.__client.get_resource(identifier)
                e.set_configuration(config)
                return self.__serialize(e, wfile)
            else:
    
                logger.debug("ADD %s" % identifier)
        
                logger.debug(typename)
                logger.debug(config)
                e = self.__client.add_resource(identifier, name, typename, config, None)
        except LookupError:
            logger.debug("Failed to resolve: " + identifier)
            raise HTTPError(404)
        except Exception, e:
            logger.exception("error during POST")
            raise HTTPError(500, str(e))
        
        self.__serialize(e, wfile)


    
    def do_DELETE(self, path, rfile, wfile, headers):
        # as action
        #cl = headers["Content-Length"]
        #request = dfile.read(int(cl))
        #buffer = StringIO(request)
        #identifier = Identifier(path)

        identifier = self.__get_identifier(path)
        logger.debug("DELETE %s" % identifier)
        #
        #try:
        #    typename, config, action = self.__serializer.unserialize(buffer)
        #finally:
        #    buffer.close()


        
        e = self.__client.get_resource(identifier)
        e.delete()
        
        #logger.debug("Deleted User: " + unicode(name))


    def __serialize(self, resource, wfile):
        buffer = StringIO()
        try:
            self.__serializer.serialize(resource, buffer)
            response = buffer.getvalue()
        finally:
            buffer.close()

        logger.debug("writing response:" + response)
        wfile.write(response)
        

import BaseHTTPServer
from BaseHTTPServer import BaseHTTPRequestHandler
import SocketServer
from cStringIO import StringIO

class RESTServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer, RestFrontend):
    class RequestHandler(BaseHTTPRequestHandler):
        def __getattr__(self, a):
            logger.debug("getattr: " + a)
            if not a.startswith("do_"):
                raise AttributeError(a)
            m = getattr(self.server, a)
            def handler():
                wfile = StringIO()
                try:
                    logger.debug("Executing")
                    m(self.path, self.rfile, wfile, self.headers)
                    content = wfile.getvalue()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/xml")
                    self.send_header("Content-Length", str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                except HTTPError, e:
                    msg = str(e)
                    if not msg:
                        msg = None
                    self.send_error(e.code, msg)
                except Exception, e:
                    logger.exception("Error during request")
                    self.send_error(500, str(e))
                finally:
                    wfile.close()

            return handler    

    def __init__(self, address, registry_url, prefix):
        BaseHTTPServer.HTTPServer.__init__(self, address, RESTServer.RequestHandler)
        RestFrontend.__init__(self, registry_url, prefix)

class RESTFrontendApplication(RestFrontend):   
    def __call__(self, environ, start_response):
        rfile = environ["wsgi.input"]
        method = environ["REQUEST_METHOD"]
        wfile = StringIO()
        path = environ["PATH_INFO"]
        headers = environ
        if "CONTENT_TYPE" in headers:
            headers["Content-Type"] = headers["CONTENT_TYPE"]
        if "CONTENT_LENGTH" in headers:
            headers["Content-Length"] = headers["CONTENT_LENGTH"]
        
        f = getattr(self, "do_" + method)
        try:
            f(path, rfile, wfile, headers)
            content = wfile.getvalue()
            resp = "200 OK"
            ct = "application/xml"
        except Exception, e:
            logger.exception("Error in RESTFrontend: %s" % (e, ))
            resp = "500 %s" % (e,)
            content = "<html><head><title>%s</title></head><body><h1>%s</h1></body></html>" % (resp, repr(e), )
            ct = "text/html"
        
        headers = [ ("Content-Type", ct), ("Content-Length", str(len(content))) ]
        start_response(resp, headers)
        return [ content ]
    
def main():
    import sys

    console = logging.StreamHandler()
    formatter = logging.Formatter('REST: %(levelname)s [%(funcName)s(%(filename)s:%(lineno)s] - %(message)s')
    console.setFormatter(formatter)
    console.setLevel(logging.DEBUG)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(console)

    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 8001

    logger.debug("Starting")
    r = RESTServer(("0.0.0.0", port), "http://127.0.0.1:8000", "test")
    r.serve_forever()
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
