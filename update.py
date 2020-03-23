# CanCyber Zeek Module Updater Python Script v2.1.01 2020 03 22
import os
import requests
import re
import time


url = "https://tool.cancyber.org/get/indicators"
local = os.path.dirname(os.path.realpath(__file__))

def download(filename, name):
   print(filename)
   try:
      mtime = int(os.path.getmtime(local + '/' + str(filename)))
      diff = int(time.time())-mtime
      
      print ("  file is " + str(diff) + " seconds old")
      if diff < 3600:
         print ("   less than an hour, skipping update")
         return
   except:
      None
   r = requests.get(url, params={'toolkey': key, 'query': name, 'version': 'updater', 'zeekversion': '0'})
   if r.status_code == 200:
     try:
        if len(r.text) > 100 and r.text[0] == '#':
           f = open(local + '/' + str(filename), "w")
           f.write(r.text)
           f.close()
     except Exception as (e):
        print("Error: " + str(e))




if os.path.isfile(local + '/config.zeek'):
   f = open(local + '/config.zeek', "r")
   fcontent = f.read()

   m = re.search('APIKEY = "([a-f0-9]{64})"', fcontent)
   key = m.group(1)

   source = "zeek"
   m = re.search('CCSOURCE = "(.*?)"', fcontent)
   if m:
      source = m.group(1)


print("CanCyber.org toolkey="+ str(key))
print("   Zeek rule type=" + str(source))


if os.path.isfile(local + '/scripts/cancyber_sigs.zeek'):
   download("/scripts/cancyber_sigs.zeek", "cancyber_sigs.zeek")
else:
   print("missing " + str(local) + '/scripts/cancyber_sigs.zeek')
   download("/scripts/cancyber_sigs.zeek", "cancyber_sigs.zeek")


if os.path.isfile(local + '/scripts/cancyber_sigs.sig'):
   download("/scripts/cancyber_sigs.sig", source)
else:
   print("missing " + str(local) + '/scripts/cancyber_sigs.sig')
   download("cancyber_sigs.sig", source)


if os.path.isfile(local + '/scripts/cancyber_expire.zeek'):
   download("/scripts/cancyber_expire.zeek", "cancyber_expire.zeek")
else:
   print("missing " + str(local) + '/scripts/cancyber_expire.zeek')
   download("/scripts/cancyber_expire.zeek", "cancyber_expire.zeek")


