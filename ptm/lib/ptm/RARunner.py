'''
Created on 05.10.2010

@author: kca
'''

from ptm.ManagerServer import ManagerServer
import sys


def RARunner(fullname):
    import logging
    logger = logging.getLogger("ptm")
    console = logging.StreamHandler()
    formatter = logging.Formatter('Manager: %(levelname)s [%(funcName)s(%(filename)s:%(lineno)s] - %(message)s')
    console.setFormatter(formatter)
    console.setLevel(logging.DEBUG)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(console)

    module, _, klassname = fullname.rpartition(".")
    
    if not module or not klassname:
        raise ValueError("Not a fully qualified class name: %s" % (fullname, ))

    print("importing module: %s" % (module, ))
    
    __import__(module)
    module = sys.modules[module]
    klass = getattr(module, klassname)
    
    m = ManagerServer(None)
    a = klass(manager = m.manager)
    m.serve_forever()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Missing argument.")
        sys.exit(1)
    RARunner(sys.argv[1])
