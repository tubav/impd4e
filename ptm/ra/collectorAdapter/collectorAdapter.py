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

import os, shlex, paramiko

from Node import Node

logger = logging.getLogger("ptm")

# Create temporary folder
cmd_mkdir = "mkdir collector"

# Install command for java
cmd_install_java = "sudo apt-get install openjdk-6-jdk"

# Install command for screen
cmd_install_screen = "sudo apt-get install screen"

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

		exportFolder = "empty"
		exportFormat = "empty"
		exportHost = "empty"
		ttlcheck = "empty"
		
		hostname = "empty"
		public_ip = "empty"
		password = "empty"
		resource = "empty"
		install = False
		collector = "empty"
		collector_id = "empty"

		if config.has_key("exportFolder"):
			exportFolder = config["exportFolder"].strip('s')

		if config.has_key("exportFormat"):
			exportFormat = config["exportFormat"].strip('s')

		if config.has_key("exportHost"):
			exportHost = config["exportHost"].strip('s')

		if config.has_key("ttlcheck"):
			ttlcheck = "yes"

		if config.has_key("resource"):
			resource = config["resource"]

		if config.has_key("target"):
			if resource != "empty":
				target = config["target"]
				configuration = target.get_adapter().get_configuration(resource)
				hostname = configuration["hostname"]
				public_ip = configuration["public_ip"]
				password = configuration["password"]

		if config.has_key("install"):
			install = True

		if config.has_key("collector"):
			collector = config["collector"]

		if config.has_key("id"):
			collector_id = config["id"]

		logger.debug("------------------------------------------------------")
		logger.debug("--> Number of entered parameters: "+str(configLength))
		logger.debug("--> exportFolder = "+exportFolder)
		logger.debug("--> exportFormat = "+exportFormat)
		logger.debug("--> exportHost = "+exportHost)
		logger.debug("--> ttlcheck = "+ttlcheck)
		logger.debug("--> resource = "+resource)
		logger.debug("--> hostname = "+hostname)
		logger.debug("--> public_ip = "+public_ip)
		logger.debug("--> password = "+password)
		logger.debug("--> install = "+str(install))
		logger.debug("--> collector = "+collector)
		logger.debug("--> id = "+collector_id)
		logger.debug("------------------------------------------------------")

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
		if (public_ip == "empty"):
			if (collector == "empty"):
				cmd = "java -Dmainclass=de.fhg.fokus.net.packetmatcher.Matcher -cp org.kohsuke.args4j.Starter -jar /home/collector/packetmatcher-1.0-SNAPSHOT-jar-with-dependencies.jar"
			else:
				cmd = "java -Dmainclass=de.fhg.fokus.net.packetmatcher.Matcher -cp org.kohsuke.args4j.Starter -jar "+collector+"packetmatcher-1.0-SNAPSHOT-jar-with-dependencies.jar"
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
			if (collector_id != "empty"):
				n = collector_id
				name = n
				i = n
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

		if (public_ip == "empty"):
			self.run_local(cmd,i)
		else:
			#self.run_remote(cmd,i,hostname,public_ip,password,install,collector)
			self.run_remote(cmd,i,"prism",public_ip,password,install,collector)

                return name

	def execute_command(self,channel,cmd,password):

                channel.send(cmd)

                resp = ""
                while resp.find("$") == -1:
                        resp = channel.recv(1000000)
                        logger.debug(resp)

                        if resp.find("password") != -1:
                                logger.debug("--- password needed! ---")
                                channel.send(password+"\n")

        def wait_for_new_execute(self,channel):

                resp = ""
                while resp.find("$") == -1:
                        resp = channel.recv(1000000)
                        logger.debug(resp)

        def command_available(self,channel,cmd):

                channel.send(cmd)
                available = True

                resp = ""
                while resp.find("$") == -1:
                        resp = channel.recv(1000000)
                        logger.debug(resp)

                        if resp.find("command not found") != -1:
                                available = False

                return available

	def run_remote(self,cmd,i,hostname,public_ip,password,install,collector):

		logger.debug("--- copying collector to machine "+public_ip+" ...")

		global cmd_mkdir
		global cmd_install_java
		global cmd_install_screen

		# Initialize Client and Channel.
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(public_ip,username=hostname,password=password)

                # Logging in.
                channel = client.invoke_shell()
                self.wait_for_new_execute(channel)

                if (install == True):
			# install important resources
                        self.execute_command(channel,cmd_mkdir+'\n',password)
                        self.execute_command(channel,cmd_install_java+'\n',password)
			self.execute_command(channel,cmd_install_screen+'\n',password)
			# Copy collector
			sftp = client.open_sftp()
			if (collector == "empty"):
				sftp.put("/home/collector/packetmatcher-1.0-SNAPSHOT-jar-with-dependencies.jar","collector/packetmatcher-1.0-SNAPSHOT-jar-with-dependencies.jar")
			else:
				sftp.put(collector+"packetmatcher-1.0-SNAPSHOT-jar-with-dependencies.jar","collector/packetmatcher-1.0-SNAPSHOT-jar-with-dependencies.jar")

		logger.debug("--- starting collector on machine "+public_ip+" ...")

		cmd_execute = "screen -m -d -S collector"+str(i)+" "+cmd
		self.execute_command(channel,cmd_execute+'\n',password)

		logger.debug("--- collector started on machine "+public_ip+" ---")


	def run_local(self,cmd,i):
		logger.debug("--- starting collector on this machine ... --- ")

		cmd_execute = "screen -m -d -S collector"+str(i)+" "+cmd
		logger.debug(cmd_execute)
		os.system(cmd_execute)

		logger.debug("--- collector started on this machine! ---")


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

