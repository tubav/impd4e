'''
Created on 8.8.2011

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

import os, shlex

logger = logging.getLogger("ptm")

class collectorAdapter(AbstractResourceAdapter):
        '''
        classdocs
        '''

        def __init__(self, manager, *args, **kw):
                super(collectorAdapter, self).__init__(*args, **kw)
                self.__instances = set("0")
                manager.register_adapter("/collectorResource", self)

        def list_resources(self, parent, typename):
                assert(typename == "collectorResource" or not typename)
                assert(parent == None)
                return [ Identifier("/collectorResource-" + i) for i in self.__instances ]


        def add_resource(self, parent_id, name, typename, config, owner = None):
	
		assert(typename == "collectorResource")

		configLength = len(config)

		host = "empty"
		exportFolder = "empty"
		exportFormat = "empty"
		exportHost = "empty"
		ttlcheck = "empty"

		if config.has_key("host"):
			host = config["host"].strip('s')

		if config.has_key("exportFolder"):
			exportFolder = config["exportFolder"].strip('s')

		if config.has_key("exportFormat"):
			exportFormat = config["exportFormat"].strip('s')

		if config.has_key("exportHost"):
			exportHost = config["exportHost"].strip('s')

		if config.has_key("ttlcheck"):
			ttlcheck = "yes"

		logger.debug("------------------------------------------------------")
		logger.debug("--> Number of entered parameters: "+str(configLength))
		logger.debug("--> host = "+host)
		logger.debug("--> exportFolder = "+exportFolder)
		logger.debug("--> exportFormat = "+exportFormat)
		logger.debug("--> exportHost = "+exportHost)
		logger.debug("--> ttlcheck = "+ttlcheck)
		logger.debug("------------------------------------------------------")

		# Host Parsing
		hostIPs = [] # result host IP's
    		hostNames = [] # result host names
    		currHost = ""
    		remainingHosts = host

    		while(remainingHosts != ""):

        		semicolon_index = remainingHosts.find(";")
        		if (semicolon_index != -1):
            			# Multiple hosts found
            			currHost = remainingHosts[0:semicolon_index]
            			remainingHosts = remainingHosts[semicolon_index+1:len(remainingHosts)]

     			else:
            			currHost = remainingHosts
            			remainingHosts = ""

        		comma_index = currHost.find(":")

        		# Saving the current host information
        		if (comma_index != -1):
            			hostIPs = hostIPs + [currHost[0:comma_index]]
            			hostNames = hostNames + [currHost[comma_index+1:len(currHost)]]

		# Export Format Parsing
		exportInCSV = "No";
    		exportInObj = "No";

    		if (exportFormat == "csv"):
        		exportInCSV = "Yes";

    		if (exportFormat == "obj"):
        		exportInObj = "Yes";

    		if (exportFormat == "csv+obj"):
        		exportInCSV = "Yes";
        		exportInObj = "Yes";

		# ExportHost Parsing
                exportHostIP = "empty"
                exportHostPort = "empty"
                exportInterval = "empty"

    		exportHost_index_1 = exportHost.find(":")

    		if (exportHost_index_1 != -1):
        		exportHostIP = exportHost[0:exportHost_index_1]
        		exportHostPart2 = exportHost[exportHost_index_1+1:len(exportHost)]
        
        		exportHost_index_2 = exportHostPart2.find(":")

        		if (exportHost_index_2 != -1):
            			exportHostPort = exportHostPart2[0:exportHost_index_2]
            			exportInterval = exportHostPart2[exportHost_index_2+1:len(exportHostPart2)]

       	 		else:
            			exportHostPort = exportHostPart2
            			exportInterval = "7"

		# Writing the command
		if (hostIPs == []):
			cmd = "java -Dmainclass=de.fhg.fokus.net.packetmatcher.Matcher -cp org.kohsuke.args4j.Starter -jar ~/collector/packetmatcher-1.0-SNAPSHOT-jar-with-dependencies.jar"
		else:
			cmd = "java -Dmainclass=de.fhg.fokus.net.packetmatcher.Matcher -cp org.kohsuke.args4j.Starter -jar collector/packetmatcher-1.0-SNAPSHOT-jar-with-dependencies.jar"

		if (exportInCSV == "Yes"):
                        cmd = cmd + " -csv"

                if (exportInObj == "Yes"):
                        cmd = cmd + " -obj"

    		if (exportFolder != "empty"):
        		cmd = cmd + " -exportFolder "+exportFolder

    		if (exportHostIP != "empty"):
        		cmd = cmd + " -exportHost "+exportHostIP

    		if (exportHostPort != "empty"):
        		cmd = cmd + " -exportPort "+exportHostPort

    		if (exportHostPort != "empty"):
        		cmd = cmd + " -exportReconnectInterval " + exportInterval

    		if (ttlcheck == "yes"):
        		cmd = cmd + " -ttlcheck"

		n = name
                if not name:
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

		if (hostIPs == []):
			self.run_local(cmd,i)
		else:
			self.run_remote(cmd,i,hostNames,hostIPs)

                return name

	def run_remote(self,cmd,i,hostNames,hostIPs):

		logger.debug("--- copying collector to machine "+hostIPs[len(hostIPs)-1]+" ...")

		# Currently it only works if the path contains one ssh-connection !!!
		cmd_copy_collector = "scp -r ~/collector/ "+hostNames[len(hostIPs)-1]+"@"+hostIPs[len(hostIPs)-1]+":."
		os.system(cmd_copy_collector)

		logger.debug("--- starting collector on machine "+hostIPs[len(hostIPs)-1]+" ...")

		cmd_execute = "screen -m -S collector"+str(i)+" "+cmd

		login = ""
    		for i in range(0,len(hostIPs)):
        		login = login + "ssh -t " + hostNames[i] + "@" + hostIPs[i] + " "

		logger.debug(login+cmd_execute)
		os.system(login+cmd_execute)

		logger.debug("--- Collector started on machine "+hostIPs[len(hostIPs)-1]+" ---")

	def run_local(self,cmd,i):
		logger.debug("--- starting collector on this machine ... --- ")

		cmd_execute = "screen -m -S collector"+str(i)+" "+cmd
		logger.debug(cmd_execute)
		os.system(cmd_execute)

		logger.debug("--- Collector started on this machine! ---")


        def have_resource(self, identifier):
                assert(identifier.parent == None)
                assert(identifier.typename == "collectorResource")
                return identifier.name in self.__instances


        def get_resource(self, identifier):
                return identifier


        def get_configuration(self, identifier):
                assert(identifier.parent == None)
                assert(identifier.typename == "collectorResource")

                if not self.have_resource(identifier):
                        raise InstanceNotFound(identifier)

                return {}


        def set_configuration(self, identifier, config):
                assert(identifier.parent == None)
                assert(identifier.typename == "collectorResource")
                return


        def get_attribute(self, identifier, name):
                assert(identifier.parent == None)
                assert(identifier.typename == "collectorResource")
                raise ConfigurationAttributeError(name)


        def set_attribute(self, identifier, name, value):
                assert(identifier.parent == None)
                                                                 
                                                                         
        def delete_resource(self, identifier, owner, force = False):
                assert(identifier.parent == None)
                assert(identifier.typename == "collectorResource")
                self.__instances.pop(identifier.resourcename)

