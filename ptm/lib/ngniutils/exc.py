'''
Created on 14.07.2011

@author: kca
'''

def errorstr(e):
	try:
		message = e.message
	except AttributeError:
		message = str(e)
	else:
		if not message:
			message = str(e)
	return message