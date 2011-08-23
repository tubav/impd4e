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

import os, subprocess, shlex, paramiko
from subprocess import Popen
from subprocess import PIPE

logger = logging.getLogger("ptm")
ipaddress = "empty"

# --- install commands ----

# Create temporary folder
cmd_mkdir = "mkdir probe_installation ; cd probe_installation"

# Install command for gcc
cmd_install_gcc = "sudo apt-get -y install gcc"

# Install command for screen
cmd_install_screen = "sudo apt-get -y install screen"

# Install command for git-core
cmd_install_git_core = "sudo apt-get -y install git-core"

# Install command for libpcap
cmd_install_libpcap = "sudo apt-get -y install libpcap-dev"

# Install commands for libev
cmd_download_libev = "wget http://dist.schmorp.de/libev/libev-4.04.tar.gz"
cmd_extract_libev = "tar -xf libev-4.04.tar.gz ; cd libev-4.04"
cmd_install_libev = "./configure ; make ; sudo make install ; cd .."

# Install commands for libipfix
cmd_download_libipfix = "git clone git://libipfix.git.sourceforge.net/gitroot/libipfix/libipfix ; cd libipfix"
cmd_install_libipfix = "./configure ; make ; sudo make install ; cd .."

# Install commands for impd4e
cmd_install_software_properties = "sudo apt-get install python-software-properties"
cmd_add_repo = "sudo add-apt-repository ppa:pt-team/pt"
cmd_update = "sudo apt-get update"
cmd_install_impd4e = "sudo apt-get install impd4e ; cd .."

# Delete temporary folder
cmd_rm_dir = "sudo rm -rf probe_installation/"

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
		location = "52:13:2" # default location (Berlin)
		collector = ipaddress+":"+"4739"
		packetFilter = ""
		samplingRatio = "100.0"
		install = False
		
		hostname = "empty"
                public_ip = "empty"
                password = "empty"
                resource = "empty"

		configLength = len(config)

		if config.has_key("probe"):
			probe = config["probe"].strip('s')

		if config.has_key("location"):
			location = config["location"].strip('s')

		if config.has_key("collector"):
			collector = config["collector"].strip('s')

		if config.has_key("packetFilter"):
			packetFilter = config["packetFilter"].strip('s')
			
		if config.has_key("samplingRatio"):
			samplingRatio = config["samplingRatio"].strip('s')

		if config.has_key("install"):
			install = True

		if config.has_key("resource"):
                        resource = config["resource"]

		if config.has_key("target"):
                        if resource != "empty":
                                target = config["target"]
                                configuration = target.get_adapter().get_configuration(resource)
                                hostname = configuration["hostname"]
                                public_ip = configuration["public_ip"]
                                password = configuration["password"]


		logger.debug("--------------------------------------------------")
		logger.debug("--> Number of entered parameters: "+str(configLength))
		logger.debug("--> probe = "+probe)
		logger.debug("--> location = "+location)
		logger.debug("--> collector = "+collector)
		logger.debug("--> filter = "+packetFilter)
		logger.debug("--> samplingRatio = "+samplingRatio)
		logger.debug("--> install = "+str(install))
		logger.debug("--> hostname = "+hostname)
		logger.debug("--> public_ip = "+public_ip)
		logger.debug("--> password = "+password)
		logger.debug("--> resource = "+resource)
		logger.debug("--------------------------------------------------")

    		indexCollectorSplit = collector.find(":")
    		collectorIP = collector[0:indexCollectorSplit]
    		collectorPort = collector[indexCollectorSplit+1:len(collector)]		

		n = probe
                if not name:
			if config.has_key("probe"):
				n = probe
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

		cmd = "sudo /usr/bin/impd4e -i i:"+interface+" -C "+collectorIP+" -P "+collectorPort+" -o "+probe+" -l "+location+" -r "+samplingRatio

		if (packetFilter != ""):
			cmd = cmd + " -f "+packetFilter

		if (public_ip == "empty"):
			self.run_local(cmd,probe)
		else:
			#self.run_remote(cmd,probe,hostname,public_ip,password,install)
			self.run_remote(cmd,probe,"prism",public_ip,password,install)
			
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

	def run_remote(self,cmd,probe,hostname,public_ip,password,install):
		logger.debug("--- starting impd4e on machine "+public_ip+" ...")

		global cmd_mkdir
		global cmd_install_gcc
		global cmd_install_screen
		global cmd_install_git_core
		global cmd_install_libpcap
		global cmd_download_libev
		global cmd_extract_libev
		global cmd_install_libev
		global cmd_download_libipfix
		global cmd_install_libipfix
		global cmd_install_software_properties
                global cmd_add_repo
                global cmd_update
                global cmd_install_impd4e
		cmd_execute = "screen -m -d -S probe"+probe+" "+cmd
		logger.debug(cmd_execute)

		# Initialize Client and Channel.
		client = paramiko.SSHClient()
		client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		client.connect(public_ip,username=hostname,password=password)

		# Logging in.
		channel = client.invoke_shell()
		self.wait_for_new_execute(channel)

		if (install == True):
			# Create temporary folder
			self.execute_command(channel,cmd_mkdir+'\n',password)
			# Install gcc
			self.execute_command(channel,cmd_install_gcc+'\n',password)
			# Install screen
			self.execute_command(channel,cmd_install_screen+'\n',password)
			# Install git-core
			self.execute_command(channel,cmd_install_git_core+'\n',password)
			# Install libpcap
			self.execute_command(channel,cmd_install_libpcap+'\n',password)
			# Install libev
			self.execute_command(channel,cmd_download_libev+'\n',password)
			self.execute_command(channel,cmd_extract_libev+'\n',password)
			self.execute_command(channel,cmd_install_libev+'\n',password)
			# Install libipfix
			self.execute_command(channel,cmd_download_libipfix+'\n',password)
			self.execute_command(channel,cmd_install_libipfix+'\n',password)
			# Get newest version of impd4e
			self.execute_command(channel,cmd_install_software_properties+'\n',password)
			self.execute_command(channel,cmd_add_repo+'\n',password)
			self.execute_command(channel,cmd_update+'\n',password)
			self.execute_command(channel,cmd_install_impd4e+'\n',password)
			# Delete temporary folder
			self.execute_command(channel,cmd_rm_dir+'\n',password)

		# start impd4e
		self.execute_command(channel,cmd_execute+'\n',password)
		
		# Close channel and client
		channel.close()
		client.close()

		logger.debug("--- impd4e started on machine "+public_ip+" ---")

	def run_local(self,cmd,probe):
		logger.debug("--- starting impd4e on this machine ... --- ")

		global cmd_install_software_properties
		global cmd_add_repo
		global cmd_update
		global cmd_install_impd4e

		cmd_execute = "screen -m -S probe"+probe+" "+cmd
		
		logger.debug(cmd_execute)

		os.system(cmd_install_software_properties)
		os.system(cmd_add_repo)
		os.system(cmd_update)
		os.system(cmd_install_impd4e)
		os.system(cmd_execute)

		logger.debug("--- impd4e started on this machine! ---")


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

