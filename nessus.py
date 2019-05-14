# -*-coding:Utf-8 -*
import requests
import json

# 07/01/2016
# informations
# https://cloud.tenable.com/api

#----------------------------------------------------------
# DON T WORK TO START SCAN ANY MORE TEENABLE AS CLOSE A PART OF IS API ...
#----------------------------------------------------------

# disable ssl warning (bad) / see sslVerify parameter
import urllib3
urllib3.disable_warnings()

class nessus:
	"""Nessus API"""
	def __init__(self,server='localhost',port=8834):
		self.server=server
		self.port=str(port)
		self.url="https://%s:%s"%(self.server,self.port)
		self.token=""
		self.sslVerify=False
		self.apiKeys=""

	def status(self):
		""" Get status of the server """
		""" {"code":200,"progress":null,"status":"ready"} """
		path=self.url+"/server/status"
		response=requests.get(path,verify=self.sslVerify)
		# .text .header .status_code
		if response.status_code == 200:
			return json.loads(response.text)
		else:
			return False

	def properties(self):
		""" Get properties of the server"""
		""" {"nessus_type":"Nessus Home","server_version":"6.9.3","nessus_ui_build":"76","nessus_ui_version":"6.9.3","server_build":"M20076"} """
		path=self.url+"/server/properties"
		response=requests.get(path,verify=self.sslVerify)
		# .text .header .status_code
		if response.status_code == 200:
			return json.loads(response.text)
		else:
			return False

	def getToken(self,user,password):
		""" Creates a new session token for the given user. """
		""" {"token":"f702e0eb3e195a79axxxxxxxxxx"} """
		""" 200 OK | 400 user format is not valide | 401 user or password invalide | 500 too many user"""
		payload="{\"username\":\"%s\", \"password\":\"%s\"}"%(user,password)
		path=self.url+"/session"
		headers={'Content-Type': 'application/json'}
		response=requests.post(path,data=payload,headers=headers,verify=self.sslVerify)
		# .text .header .status_code
		if response.status_code == 200:
			self.token = json.loads(response.text)['token']
			return json.loads(response.text)
		else:
			self.token = False
			return False

	def addKeys(self,accessKey,secretKey):
		""" add nessus api secret and secet key """
		""" recommanded usage / no timeeout"""
		self.apiKeys='accessKey=%s; secretKey=%s;'%(accessKey, secretKey)
	
	def deleteToken(self):
		""" Logs the current user out and destroys the session """
		""" 200 destroy | 401 no session """
		path=self.url+"/session"
		headers={'X-Cookie': 'token='+self.token}
		response=requests.delete(path,headers=headers, verify=self.sslVerify)
		if response.status_code == 200:
			return True
		else:
			return False

	def getFolders(self):
		""" Return the current user's scan folders """
		path=self.url+"/folders"
		headers={'X-Cookie': 'token='+self.token,'X-ApiKeys': self.apiKeys}
		response=requests.get(path,headers=headers, verify=self.sslVerify)
		if response.status_code == 200:
			return json.loads(response.text)
		else:
			return False

	def getPolicies(self):
		""" Return the current user's policies """
		path=self.url+"/policies"
		headers={'X-Cookie': 'token='+self.token,'X-ApiKeys': self.apiKeys}
		response=requests.get(path,headers=headers, verify=self.sslVerify)
		if response.status_code == 200:
			return json.loads(response.text)
		else:
			return False


	def getTemplates(self):
		""" Return templates """
		path=self.url+"/editor/policy/templates"
                headers={'X-Cookie': 'token='+self.token,'X-ApiKeys': self.apiKeys}
                response=requests.get(path,headers=headers, verify=self.sslVerify)
		if response.status_code == 200:
			return json.loads(response.text)
		else:
			return False

	def createScan(self,uuid,settings):
		""" Create a scan in nessus """
		""" uuid template, setting is a dictionnary {"name": "scanName",...}"""
		path=self.url+"/scans"
                headers={'X-Cookie': 'token='+self.token,'X-ApiKeys': self.apiKeys, 'Content-Type': 'application/json'}
		payload='{"uuid": "%s", "settings": %s}'%(uuid, json.dumps(settings))
		response=requests.post(path,data=payload,headers=headers,verify=self.sslVerify)
		if response.status_code == 200:
			return json.loads(response.text)
		else:
			return False

	def startScan(self,scanId):
		""" launch the scan id """
		path="%s/scans/%s/launch"%(self.url,scanId)
		headers={'X-Cookie': 'token='+self.token,'X-ApiKeys': self.apiKeys}
		response=requests.post(path,headers=headers,verify=self.sslVerify)
		if response.status_code == 200:
			return json.loads(response.text)
		else:
			return False

	def getScan(self,scanId):
		""" scan info """
		""" .info.status """
		path="%s/scans/%s"%(self.url,scanId)
		headers={'X-Cookie': 'token='+self.token,'X-ApiKeys': self.apiKeys}
		response=requests.get(path,headers=headers, verify=self.sslVerify)
		if response.status_code == 200:
			return json.loads(response.text)
		else:
			return False

	def getHost(self,scanId,hostId):
		""" get host info in scan folder """
		path="%s/scans/%s/hosts/%s"%(self.url,scanId,hostId)
		headers={'X-Cookie': 'token='+self.token,'X-ApiKeys': self.apiKeys}
		response=requests.get(path,headers=headers, verify=self.sslVerify)
		if response.status_code == 200:
			return json.loads(response.text)
		else:
			return False

	def getVulnerabilities(self,scanId,hostId,pluginId):
		""" get information about plugin detection """
		path="%s/scans/%s/hosts/%s/plugins/%s"%(self.url,scanId,hostId,pluginId)
		headers={'X-Cookie': 'token='+self.token,'X-ApiKeys': self.apiKeys}
		response=requests.get(path,headers=headers, verify=self.sslVerify)
		if response.status_code == 200:
			return json.loads(response.text)
		else:
			return False

	def listScan(self,folderId):
		""" get json list of scan of the folder ID """
		path="%s/scans?folder_id=%s"%(self.url,folderId)
                headers={'X-Cookie': 'token='+self.token,'X-ApiKeys': self.apiKeys}
                response=requests.get(path,headers=headers, verify=self.sslVerify)
                if response.status_code == 200:
                        return json.loads(response.text)['scans']
                else:
                        return False

	def getPluginInfo(self,pluginId):
		""" return plugin id information """
                path="%s/plugins/plugin/%s"%(self.url,pluginId)
                headers={'X-Cookie': 'token='+self.token,'X-ApiKeys': self.apiKeys}
                response=requests.get(path,headers=headers, verify=self.sslVerify)
                if response.status_code == 200:
                        return json.loads(response.text)
                else:
                        return False

