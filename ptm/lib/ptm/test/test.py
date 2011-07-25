'''
Created on 13.08.2010

@author: kca
'''

from ptm.ManagerServer import ManagerServer
from ptm.ra.SimpleTestAdapter import SimpleTestAdapter

def main():
    import logging
    logger = logging.getLogger("ptm")
    console = logging.StreamHandler()
    formatter = logging.Formatter('Manager: %(levelname)s [%(funcName)s(%(filename)s:%(lineno)s] - %(message)s')
    console.setFormatter(formatter)
    console.setLevel(logging.DEBUG)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(console)

    logger.debug("huhu")
    m = ManagerServer(None)
    a = SimpleTestAdapter(manager = m.manager)
    m.serve_forever()

if __name__ == '__main__':
    main()