#!/usr/bin/env python
#coding=utf8

'''
Created on MAY 18, 2013

@author: zjsfmy
'''

try:
    import os
    import sys
    import urllib
    import urllib2
    import json
    import rsa
    import binascii
    import time

except ImportError:
        print >> sys.stderr, """\

There was a problem importing one of the Python modules required.
The error leading to this problem was:

%s

Please install a package which provides this module, or
verify that the module is installed correctly.

It's possible that the above module doesn't match the current version of Python,
which is:

%s

""" % (sys.exc_info(), sys.version)
        sys.exit(1)


__prog__= "BISTU_API_login for python"
__site__= "http://fmyzjs.github.com"
__version__="0.1 beta"



app_key = 'yours'
app_pass = 'yours'

def get_login_pubkey():
    args = {
        'app_key': app_key,
        'app_pass': app_pass,
        'table': 'member',
        'action': 'getloginkey'
        }

    data = urllib2.urlopen('http://api.bistu.edu.cn/api/api_app.php?' + urllib.urlencode(args)).read()
    try:
        data = json.loads(data)
        pubkey = data
        return pubkey
    except:
        return None

def get_info_rsa(username, password , loginkey):
    """
        Get rsa2 encrypted password, using RSA module from https://pypi.python.org/pypi/rsa/3.1.1, documents can be accessed at 
        http://stuvel.eu/files/python-rsa-doc/index.html
    """
    #n, n parameter of RSA public key, which is published by api.bistu.edu.cn
    #hardcoded here but you can also find it from values return from prelogin status above
    #loginKey = get_prelogin_pubkey()
    key = int(loginkey, 16)
    #e, exponent parameter of RSA public key, API uses 0x10001, which is 65537 in Decimal
    login_rsa_e = 65537
    unixtime = int(time.time())
    info = username + '|' + passwd +'|' + str(unixtime)   
    #construct API RSA Publickey using n and e above, note that n is a hex string
    key = rsa.PublicKey(key, login_rsa_e)
    #get encrypted password
    encropy_pwd = rsa.encrypt(info, key)
    #trun back encrypted password binaries to hex string
    return binascii.b2a_hex(encropy_pwd)

def login(username, password, info):
    """
    Perform login action with use name, password .
    @param username: login user name
    @param passwd: login password
    """
    #GET data 
    login_data = {
        'app_key': app_key,
        'app_pass': app_pass,
        'table': 'member',
        'action': 'login',
        'info': info
        }

    # GET data
    result = urllib2.urlopen('http://api.bistu.edu.cn/api/api_app.php?' + urllib.urlencode(login_data)).read();
    try:
        data = json.loads(result)
        accessToken = data['accessToken']
        user = data['username']
        idtype = data['idtype']
        userid = data['userid']
        return accessToken, user, idtype, userid
    except:
        return None



if __name__ == '__main__':
    
    username = 'yours'
    passwd = 'yours'
    try:
        loginkey = get_login_pubkey()
    except:
        print 'Getting user pubkey error!'
    else:
        try:
            info = get_info_rsa(username=username ,password=passwd ,loginkey=loginkey)
        except:
            print 'Encrypt the user information failed!'
        else:
            try:
                accessToken, user, idtype, userid= login(username=username, password=passwd ,info=info)
                print 'Login  succeeded'
                print  accessToken, user, idtype, userid
            except:
                print 'Login failed'




