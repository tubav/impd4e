#! /usr/bin/env python

import httplib
from urlparse import urlparse
from xml.dom.minidom import parse, parseString, getDOMImplementation

from ptm.Identifier import Identifier
from ptm.exc import NoAdapterFoundError
from T1EntitySerializer import T1EntitySerializer
from T1Entity import T1Entity
import StringIO

import logging
logger = logging.getLogger("ptm")


ILLEGAL_CHARS = "<" + ">"

class T1Client(object):
	
	def __init__(self, url):
		url = urlparse(url)
		self.conn = httplib.HTTPConnection(url.netloc)
		self.urlprefix = url.path
		while self.urlprefix.endswith("/"):
			self.urlprefix = self.urlprefix[:-1]

# Communication to PTM ===================================================================================
# ^^ Thank you very much for this helpful comment...
# Why not have another one? Here we go: Now come some methods!!! Fuck Yeah.
# (Sorry, its late and I'm knee deep in other peoples crap) 
	
	def __do_request(self, method, path, params = None, headers = None):
		path = self.urlprefix + path
		if headers is None:
			headers = {}
		self.conn.request(method, path, params, headers)
	# as config a dict
	def add(self, parent, name, typename, config):
		parent = Identifier(parent).identifier
		wfile = StringIO.StringIO()
		t1_serializer = T1EntitySerializer(self)
		t1_serializer.assist_serialize(typename, None, config, wfile)
		xml = wfile.getvalue()
		print xml
		wfile.close()
		params = xml
		headers = {"Content-type":"text/plain"}
		#self.conn.request("POST", parent, params, headers)
		self.__do_request("POST", parent, params, headers)
		response = self.conn.getresponse()
		if response.status != 200:
			raise Exception(response.reason)
		resp = response.read()
		_tn, cfg, _act = t1_serializer.unserialize(resp)
		return T1Entity(cfg.pop("identifier"), self, cfg)

	# TODO action update; use XMLSerializer
	def update(self, identifier, config):
		identifier = Identifier(identifier, need_full = True)
		t1_serializer = T1EntitySerializer(self)
		#wfile = StringIO.StringIO()
		req = t1_serializer.assist_serialize(identifier.typename, None, config, None, "update")
		#self.conn.request("POST", identifier, req, {"Content-type":"text/plain"})
		self.__do_request("POST", identifier, req, {"Content-type":"text/plain"})
		response = self.conn.getresponse()
		if response.status != 200:
			raise Exception(response.reason)
		resp = response.read()
		_tn, cfg, _act = t1_serializer.unserialize(resp)
		return T1Entity(identifier, self, cfg)
		
		"""
		params = config
		bla = open(config)
		params = bla.read()
                headers = {"Content-type": "text/plain"}
		self.conn.request("PUT", parent, params, headers)
		return self.conn.getresponse()
		"""
		print ("Not yet functional.")
		

	# return t1entity; use lazyloading when loading
	def get_entity(self, identifier):
		if not identifier.startswith("/"):
			identifier = "/" + identifier
		if identifier.endswith("/"):
			identifier = identifier[:-1]
		#self.conn.request("GET", unicode(identifier))
		self.__do_request("GET", unicode(identifier))
		response = self.conn.getresponse()
		if response.status != 200:
			raise Exception(response.reason)
		cfg = response.read()
		t1_serializer = T1EntitySerializer(self)
		tn, cfg, act = t1_serializer.unserialize(cfg)
		return T1Entity(identifier, self, cfg)
		#return config #, list_of_entities

	def list_entities(self, identifier):
		# TODO return list of t1entity
		#self.conn.request("GET", unicode(identifier))
		self.__do_request("GET", unicode(identifier))
		response = self.conn.getresponse()
		if response.status != 200:
			if response.reason.startswith("No adapters found for") or response.reason.startswith("NoAdapterFoundError"):
				raise NoAdapterFoundError(identifier)
			raise Exception(response.reason)
		xml_string = parse(response)
		l = []
		child = xml_string.firstChild.childNodes

                for node in child:
                        if node.nodeName != "#text":
                                identifier = node.firstChild.data
                                if identifier.startswith("//"):
                                        name, sep, id = identifier[2:].partition("/")
#                                        identifier = "/ptm_" + name + sep + id
                                        identifier = "/" + id
                                identifier = Identifier(identifier)
				l.append(T1Entity(identifier, self, None))
		return l
	

	def delete(self, identifier):
		#self.conn.request("DELETE", unicode(identifier))
		self.__do_request("DELETE", unicode(identifier))
		return self.conn.getresponse()

# dump =================================================================================
# wow, this ones even better...

	def make_html_string(self, identifier):
		#html = open("html_template.html").read()
		u = Identifier(identifier)
		p = u.get_parent()
		
		t1 = self.get(identifier)
		print "config: ", t1.config
		print "list of entities: ", t1.list_of_entities
		#info = self.get(identifier)
		
		#html = html.replace("#TITLE#", unicode(u.identifier))

		html = self.make_body(p, t1.config, t1.list_of_entities)
		
		#html = html.replace("#BODY#", self.make_body(p, info, None))
		return html
		
	# TODO make parent link (<a href=\"http://"+ self.ip + self.port + p +"\" title=\"" + p + "\">Go to parent: " + p + "</a><br /><br />)
	def make_body(self, p, config, list_of_entities):
		impl = getDOMImplementation()
		html = impl.createDocument(None, "b", None)
		
		br = html.createElement("br")
		
		# because of the severe shittiness of python regarding apostrophes there will never be a button as a link! case closed.
		"""
		parent = html.createElement("input")
		bla = "#http://"+ self.ip + self.port + "/" + p +"#"
		parent.setAttribute("onClick", "location.href="+bla)
		parent.setAttribute("type", "button")
		parent.setAttribute("name", "parent")
		parent.setAttribute("value", "Go to parent")
		html.documentElement.appendChild(parent)
		"""

		tag = html.createElement("p")
		parent = html.createElement("a")
		parent.setAttribute("href", "http://"+ self.ip + self.port + "/" + p)
		parent_text = html.createTextNode("Go to parent " + p)
		parent.appendChild(parent_text)
		tag.appendChild(parent)
		html.documentElement.appendChild(tag)

		intro = html.createElement("i")
		intro_text = html.createTextNode("Resourceinformation:")
		intro.appendChild(intro_text)
		html.documentElement.appendChild(intro)
		
		# fill html from given config
		for k, v in config.iteritems():
			tag = html.createElement("p")
			tag_value = html.createTextNode(k.title() + ": " + unicode(v) + "; Type: " + unicode(type(v)))
			tag.appendChild(tag_value)
			html.documentElement.appendChild(tag)

		html.documentElement.appendChild(br)

		intro = html.createElement("p")
                intro_text = html.createTextNode("List of subresources:")
		intro.appendChild(intro_text)
		html.documentElement.appendChild(intro)
		html.documentElement.appendChild(br)
		
		if len(list_of_entities) == 0:
			empty_text = html.createTextNode("No subscribers.")
			html.documentElement.appendChild(empty_text)
		else:
			for k, v in list_of_entities.iteritems():
				self.make_link_to_entities(html, k, v)

		html = html.toxml()
		html = html.replace("\n", "")
		html = html.replace("\t", "")
		html = html.replace("<?xml version=\"1.0\" ?>", "")
		#html = parseString(html)
		return html

	def make_link_to_entities(self, html, k, v):
		link = html.createElement("a")

		if not self.ip.startswith("http://"):
			self.ip = "http://"+self.ip

		link.setAttribute("href", self.ip + self.port + v)
		link_text = html.createTextNode(v)
		link.appendChild(link_text)
		html.documentElement.appendChild(link)
		br = html.createElement("br")
                html.documentElement.appendChild(br)
	
# DUMP ====================================================================================================================================

	def make_body_(self, givenXml):
		input = givenXml.read()
		xml = parseString(input)
		impl = getDOMImplementation()
		html = impl.createDocument(None, "b", None)
		if xml.firstChild.getAttribute("type") == "":
			open_root = html.createTextNode("<" +xml.firstChild.nodeName+  ">")
		open_root = html.createTextNode("<" +xml.firstChild.nodeName+ " type: " +xml.firstChild.getAttribute("type")+ ">")
		#open_root = html.createTextNode(xml.firstChild.nodeName+ " type: " +xml.firstChild.getAttribute("type"))
		html.documentElement.appendChild(open_root)
		br = html.createElement("br")
		html.documentElement.appendChild(br)
		
		# fill html from givenXml(input)
		# FIXME node.firstChild crashes sometimes (/pnode_0/scscf_TzdQ4YcRM8PEg_4d)
		for node in xml.firstChild.childNodes: 
			if node.firstChild != "None":
				open_tag = html.createTextNode("<" +node.nodeName+ " type: " +node.getAttribute("type")+ ">")
				#open_tag = html.createTextNode(node.firstChild.nodeName+ " type: " +node.getAttribute("type"))
				html.documentElement.appendChild(open_tag)
				link = html.createElement("a")
				#if self.ip.find("http://") == -1:
				link.setAttribute("href", "http://" + self.ip + self.port + node.firstChild.nodeValue)
				#link.setAttribute("href", self.ip + self.port + node.firstChild.nodeValue)
				link_text = html.createTextNode(node.firstChild.nodeValue)
				link.appendChild(link_text)
				html.documentElement.appendChild(link)
				close_tag = html.createTextNode("</" +node.nodeName+ ">")
				#close_tag = html.createTextNode(node.firstChild.nodeName)
		                html.documentElement.appendChild(close_tag)
				br = html.createElement("br")
		                html.documentElement.appendChild(br)
		
		close_root = html.createTextNode("</" +xml.firstChild.nodeName+ ">")
		#close_root = html.createTextNode(xml.firstChild.nodeName)
		html.documentElement.appendChild(close_root)
		return html.toxml()
