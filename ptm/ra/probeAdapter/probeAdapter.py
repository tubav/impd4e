'''
Created on 14.02.2011

@author: jkr
'''

'''
This RA should deploy a ns-3 component as a regular instance with a given ns-3 script (currently the script has to be written in Python).
'''

from ptm.Resource import Resource

from ptm.ResourceAdapter import AbstractResourceAdapter
from ptm import Identifier
from ptm.exc import InstanceNotFound, DuplicateNameError, ConfigurationAttributeError
import logging

from path import path as Path

import subprocess, shlex

from subprocess import Popen
from subprocess import PIPE

logger = logging.getLogger("ptm")
ipaddress = "empty"

class probeAdapter(AbstractResourceAdapter):
        '''
        classdocs
        '''

        def __init__(self, manager, *args, **kw):
                super(probeAdapter, self).__init__(*args, **kw)
                self.__instances = set("0")
                manager.register_adapter("/probeResource", self)
                logger.debug("---up---")
		output = Popen(["ifconfig"], stdout=PIPE).communicate()[0]
    		indexIPStart = output.find("inet addr")+10
    		indexIPEnd = output.find("Bcast")
		global ipaddress
    		ipaddress = output[indexIPStart:indexIPEnd].strip(' ')
                logger.debug("The IP-Address of this machine is: "+ipaddress)


        def list_resources(self, parent, typename):
                assert(typename == "probeResource" or not typename)
                assert(parent == None)
                return [ Identifier("/probeResource-" + i) for i in self.__instances ]


        def add_resource(self, parent_id, name, typename, config, owner = None):
	
		assert(typename == "probeResource")
	
		output = Popen(["ifconfig"], stdout=PIPE).communicate()[0]
                indexInterface = output.find(" ")
                interface = output[0:indexInterface]

		logger.debug("--------------------------------------------------")
		logger.debug("--> Interface of this machine: "+interface)

		probe = "empty"
		location = "52.51:13.40:2" # default location (Berlin)
		collector = ipaddress+":"+"4739"
		packetFilter = ""
		samplingRatio = "100.0"

		configLength = len(config)

		if config.has_key("probe"):
			probe = config["probe"].strip('s')

		if config.has_key("location"):
			location = config["location"].strip('s')

		if config.has_key("collector"):
			collector = config["collector"].strip('s')

		if config.has_key("packetFilter"):
			packet = config["packetFilter"].strip('s')

		if config.has_key("samplingRatio"):
			samplingRatio = config["samplingRatio"].strip('s')

		logger.debug("--------------------------------------------------")
		logger.debug("--> Config has the following length: "+str(configLength))
		logger.debug("--> probe = "+probe)
		logger.debug("--> location = "+location)
		logger.debug("--> collector = "+collector)
		logger.debug("--> filter = "+packetFilter)
		logger.debug("--> samplingRatio = "+samplingRatio)
		logger.debug("--------------------------------------------------")

    		indexCollectorSplit = collector.find(":")
    		collectorIP = collector[0:indexCollectorSplit]
    		collectorPort = collector[indexCollectorSplit+1:len(collector)]		

		oid = ""
		probeIP = ""
		username = ""
		n = probe
                if not name:
			if config.has_key("probe"):

				probe_index_1 = probe.find(":")
				if (probe_index_1 != -1):
    					oid = probe[0:probe_index_1]

    					probe_part = probe[probe_index_1+1:len(probe)]
    					probe_index_2 = probe_part.find(":")
    					probeIP = probe_part[0:probe_index_2]

    					username = probe_part[probe_index_2+1:len(probe_part)]

					n = oid
					name = n

					logger.debug("--> oid = "+oid)
                			logger.debug("--> probeID = "+probeIP)
                			logger.debug("--> username = "+username)
					logger.debug("--------------------------------------------------")
				else:
					oid = probe
					n = oid
					name = n

		  	else:
                        	i = 0
                        	while True:
                                	n = str(i)
                                	if n not in self.__instances:
                                        	break
                                	i += 1
                        	name = n
                else:
                       if name in self.__instances:
                                raise DuplicateNameError(parent_id, typename, name)

                self.__instances.add(n)

		if (probeIP == ""):
			self.run_local(interface,collectorIP,collectorPort,oid,location,packetFilter,samplingRatio)
		else:
			self.run_remote(interface,collectorIP,collectorPort,oid,location,packetFilter,samplingRatio,probeIP,username)

                return name

	def run_remote(self,interface,collectorIP,collectorPort,oid,location,packetFilter,samplingRatio,probeIP,username):
		logger.debug("--- starting impd4e on machine "+probeIP+" ...")
		login = username + "@" + probeIP
		cmd=["screen","-d",".-m","ssh","-tt",login,"impd4e","-i","i:"+interface,"-C",collectorIP,"-P",collectorPort,"-o",oid,"-l",location,"-r",samplingRatio,"-f",packetFilter]

	def run_local(self,interface,collectorIP,collectorPort,oid,location,packetFilter,samplingRatio):
		logger.debug("--- starting impd4e on this machine ... --- ")
                cmd=["screen","-d","-m","impd4e","-i","i:"+interface,"-C",collectorIP,"-P",collectorPort,"-o",oid,"-l",location,"-r",samplingRatio,"-f",packetFilter]
		s=subprocess.call(cmd) 
		logger.debug("--- impd4e started! ---")


        def have_resource(self, identifier):
                assert(identifier.parent == None)
                assert(identifier.typename == "probeResource")
                return identifier.name in self.__instances


        def get_resource(self, identifier):
                return identifier


        def get_configuration(self, identifier):
                assert(identifier.parent == None)
                assert(identifier.typename == "probeResource")

                if not self.have_resource(identifier):
                        raise InstanceNotFound(identifier)

                return {}


        def set_configuration(self, identifier, config):
                assert(identifier.parent == None)
                assert(identifier.typename == "probeResource")
                return


        def get_attribute(self, identifier, name):
                assert(identifier.parent == None)
                assert(identifier.typename == "probeResource")
                raise ConfigurationAttributeError(name)


        def set_attribute(self, identifier, name, value):
                assert(identifier.parent == None)
                                                                 
                                                                         
        def delete_resource(self, identifier, owner, force = False):
                assert(identifier.parent == None)
                assert(identifier.typename == "probeResource")
                self.__instances.pop(identifier.resourcename)

