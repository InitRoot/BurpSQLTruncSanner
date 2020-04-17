#
#  BurpSQLTruncationScanner - Scan for potential SQL truncation attack vectors.
#
#  Copyright (c) 2020 Frans Hendrik Botes (InitRoot)
#  Verions 0.1
#
from burp import IBurpExtender, IScannerCheck, IScanIssue, ITab, IBurpExtenderCallbacks, IExtensionHelpers, IContextMenuFactory, IContextMenuInvocation, IHttpRequestResponse
from java.io import PrintWriter
from java.net import URL
from java.util import ArrayList, List
from java.util.regex import Matcher, Pattern
import binascii
from javax import swing
from java.awt import Font, Color
import sys
import time
import threading
import base64
import re
from array import array

import json

#Global Issue List
issueList = ArrayList()

class BurpExtender(IBurpExtender, IScannerCheck, IContextMenuFactory, IHttpRequestResponse, IBurpExtenderCallbacks):
    def registerExtenderCallbacks(self, callbacks):
        sys.stdout = callbacks.getStdout()
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("SQLTruncScanner")
        callbacks.issueAlert("SQL Truncation Scanner Enabled")
        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.registerContextMenuFactory(self)      
        print ("SQL Truncation Scanner loaded.")
        print ("Copyright (c) 2020 Frans Hendrik Botes (InitRoot)")
        self.httpTraffic = None
        self.resp = None
        
        #Set Parameters for Original Reqquest to Restruct
        self.orgHost = None
        self.orgPort = None
        self.orgProtoChoice = None
        self.orgHeaders = None
        self.orgParams = None
        self.orgMethod = None
        self.orgURLPath = None
        self.orgContType = None
        self.orgBaseline = None

    #Create context menu entry
    def createMenuItems(self, invocation):
        self.context = invocation

        itemContext = invocation.getSelectedMessages()

        if itemContext > 0:
            menuList = ArrayList()
            menuItem = swing.JMenuItem(
                "Scan with SQLTruncScanner", None, actionPerformed=self.start_scan)
            menuList.add(menuItem)
            return menuList
        return None

# We are ready to start a scan for the specific request        
    def start_scan(self, event):     
        try:
            #For later use lets get what user selected.
            #Let's get what the user selected, only compatible with one item at a time. ADD check for multiple items and throw error
            scanIssues = self._callbacks.getScanIssues(None)
            httpTraffic = self.context.getSelectedMessages()
            print (len(httpTraffic))
            httpRequest = [item.request.tostring()
                           for item in httpTraffic]
            orignalRequest = ''.join(httpRequest)
            #Rebuild the request and fetch response to calculate baseline value
            self.buildRequest(orignalRequest, httpTraffic)
            #We have the baseline, time to start fuzzing
            paramFuzzer = fuzzParams(httpTraffic, self._helpers, self._callbacks)
            thread = threading.Thread(target=paramFuzzer.fuzzParams(self.orgHost, self.orgPort, self.orgProtoChoice,
                                                                    self.orgHeaders, self.orgParams, self.orgMethod, self.orgURLPath, self.orgContType, self.orgBaseline), args=())
            thread.daemon = True
            thread.start()
            print (str(len(issueList)))
            
           # issue = ScanIssue(httpTraffic[0], self._helpers)
            #self._callbacks.addScanIssue(issue)
            #paramFuzzer.fuzzParams(self.orgHost,self.orgPort,self.orgProtoChoice,self.orgHeaders,self.orgParams,self.orgMethod,self.orgURLPath,self.orgContType,self.orgBaseline)
            
        
        except UnicodeEncodeError:
            print("Error in URL decode.")
        return None

    def buildRequest(self, strRequest, httpTraffMsg):
        stdout = PrintWriter(self._callbacks.getStdout(), True)
        strorignalRequest = strRequest
        
        #Get data about the request that was right clicked
        for item in httpTraffMsg:
            try:

                httpService = item.getHttpService()
                self.httpTraffic = httpService
                host = httpService.host
                port = httpService.port
                protocol = httpService.protocol
                protoChoice = True if protocol.lower() == 'https' else False
                #Parse the text area that should contain an HTTP request.
                requestInfo = self._helpers.analyzeRequest(strorignalRequest)
                #Request data
                headers = requestInfo.getHeaders()
                bodyOffset = requestInfo.bodyOffset
                body = strorignalRequest[bodyOffset:]

                for (i, header) in enumerate(headers):
                    if header.lower().startswith("content-type:"):
                        content_type = header.split(":")[1].lower().strip()

                method = headers[0].split(" ")[0]
                urlpath = headers[0].split(" ")[1]

                #Debugging area for output and parsing
                #stdout.println(str(body))
                #stdout.println(str(headers))
                #stdout.println(str(method))
                #stdout.println(str(content_type))
                #stdout.println(str(urlpath))

                #Identify and parse parameters in the request
                if method == "GET":
                    stdout.println("[!] GET REQUEST IDENTIFIED")
                    body = urlpath.split("?")[1]
                    #print(body)
                    params = dict(x.split('=') for x in body.split('&'))

                else:
                    #Add logic here for the handling parameters in body and JSON content
                    if "json" in str(content_type) or "JSON" in str(content_type):
                        stdout.println("[!] JSON REQUEST IDENTIFIED")
                        #print(body)
                        #print("[!] BODY DONE")
                        params = json.loads(body)
                        #print(body)
                        #print(params)

                    else:
                        stdout.println("[!] POST REQUEST IDENTIFIED")
                        #print(body)
                        params = dict(x.split('=') for x in body.split('&'))
                        #print(params)

                stdout.println("[!] PARAMETERS IDENTIFIED!")
                stdout.println(params)
                stdout.println("[!] DETERMINING BASELINE")
                baselineInt = self.baseline(host, port, protoChoice, headers, params, method, urlpath, content_type)
                #Assign Parameters for Fuzzing
                self.orgHost = host
                self.orgPort = port
                self.orgProtoChoice = protoChoice
                self.orgHeaders = headers
                self.orgParams = params
                self.orgMethod = method
                self.orgURLPath = urlpath
                self.orgContType = content_type
                self.orgBaseline = baselineInt
            except Exception as ex:
                stdout.println("Problem parsing the request data" + "\n")
                stdout.println(ex)

        return 

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if (existingIssue.getIssueName() == newIssue.getIssueName()):
            return -1
        else:
            return 0

    def extensionUnloaded(self):
        print "SQL Truncation Scanner unloaded"
        return

    def postRequest(self, headers, body, args_):
        #Needed: args=[host,port,protoChoice,request]
        stdout = PrintWriter(self._callbacks.getStdout(), True)
        request = self._helpers.buildHttpMessage(headers, body)
        args_.append(request)
        t = threading.Thread(target=self.makeRequest, args=args_)
        t.daemon = True
        t.start()
        t.join()

    def makeRequest(self, host, port, protoChoice, request):
        stdout = PrintWriter(self._callbacks.getStdout(), True)
        try:
            self.resp = self._callbacks.makeHttpRequest(
                host,
                port,
                protoChoice,
                request
            )

        except Exception as ex:
            stdout.println(ex)

    def baseline(self, host, port, protoChoice, headers, body, method, urlpath, content_type):
        if "json" not in content_type.lower():
            new_body = ""
            new_body += '&'.join("%s=%s" % (key, str(val)) for (key, val) in body.iteritems())
            #print(new_body)
            
        if method == "GET":
            url1 = urlpath.split("?")[0]
            url2 = "?" + str(new_body)
            headers[0] = "GET " + str(url1) + str(url2) + " HTTP/1.1"
            self.getRequest(headers, [host, port, protoChoice])
        else:
            self.postRequest(headers, new_body, [host, port, protoChoice])

        #Here we take the lengh and status code of the body returned as a baseline
        originalReq = self._helpers.analyzeRequest(self.resp)
        reqResponse = self._helpers.analyzeResponse(self.resp)
        reqRespTxt = self.resp.tostring()
        respStatusCode = reqResponse.getStatusCode()
        resbodyOffset = reqResponse.getBodyOffset()
        respbodyLen = len(reqRespTxt[resbodyOffset:])
        baselineData = str(respStatusCode) + str(respbodyLen)
        print(baselineData)
        return baselineData


class fuzzParams():

    def __init__(self, reqres, helpers, callbacks):
        self.helpers = helpers
        self.reqres = reqres
        self.callbacks = callbacks
        
    def postRequest(self, headers, body, args_):
        #Needed: args=[host,port,protoChoice,request]
        stdout = PrintWriter(self.callbacks.getStdout(), True)
        request = self.helpers.buildHttpMessage(headers, body)
        args_.append(request)
        t = threading.Thread(target=self.makeRequest, args=args_)
        t.daemon = True
        t.start()
        t.join()

    def makeRequest(self, host, port, protoChoice, request):
        stdout = PrintWriter(self.callbacks.getStdout(), True)
        try:
            self.resp = self.callbacks.makeHttpRequest(
                host,
                port,
                protoChoice,
                request
            )

        except Exception as ex:
            stdout.println(ex)

    def fuzzParams(self, host, port, protoChoice, headers, body, method, urlpath, content_type, baseline):
        stdout = PrintWriter(self.callbacks.getStdout(), True)
        stdout.println("[!] FUZZING "+ str(len(body)) + " PARAMETERS")
        issueList.clear()
        payloadSet = {"5": '     00', "10": '          00', "15": '               00', "20": '                    00', "30": '                              00', "40": '                                        00'}
        #Let's loop through each parameter
        for param in body:
            stdout.println("    [-] FUZZING: " + str(param))   
            fuzzParameter = str(param)
            for payLSD in payloadSet:
                stdout.println("    [-] PAYLOAD: " + payLSD)
                payload = payloadSet[payLSD]
                bodd = body
                bodd[fuzzParameter] = bodd[fuzzParameter] + payload
                if "json" not in content_type.lower():
                    new_body = ""
                    new_body += '&'.join("%s=%s" % (key, str(val))
                                        for (key, val) in bodd.iteritems())
                    #print("    " + new_body)
                if method == "GET":
                    url1 = urlpath.split("?")[0]
                    url2 = "?" + str(new_body)
                    headers[0] = "GET " + str(url1) + str(url2) + " HTTP/1.1"
                    self.getRequest(headers, [host, port, protoChoice])
                else:
                    self.postRequest(headers, new_body, [host, port, protoChoice])
                #Here we take the lengh and status code of the body returned as a baseline
                reqFuzzResponse = self.helpers.analyzeResponse(self.resp)
                reqFuzzReq = self.helpers.analyzeRequest(self.resp)
                reqFuzzRespTxt = self.resp.tostring()
                respFuzzStatusCode = reqFuzzResponse.getStatusCode()
                resFuzzbodyOffset = reqFuzzResponse.getBodyOffset()
                respFuzzbodyLen = len(reqFuzzRespTxt[resFuzzbodyOffset:])
                fuzzResponseData = str(respFuzzStatusCode) + str(respFuzzbodyLen)     
                print("    " + fuzzResponseData)
                if fuzzResponseData != baseline:
                    stdout.println("    [+] POSSIBLE INJECTION DETECTED")
                    issue = ScanIssue(
                        self.reqres[0], reqFuzzReq, "SQL Truncation Scanner", fuzzParameter + " | " + payLSD, "High")
                    self.callbacks.addScanIssue(issue)

        return

## Implement the IScanIssue interface
class ScanIssue(IScanIssue):
    def __init__(self, httpService, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail + '<br/><br/><div style="font-size:8px">'\
                                'This issue was reported by SQL '\
                                'Truncation Scanner</div>'
        self._severity = severity

    def getUrl(self):
        return self._httpService.getUrl()

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0x08000000  # See http:#portswigger.net/burp/help/scanner_issuetypes.html

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return ("SQL Truncation can occur with mySQL databases whenever the parameter received exceeds the column length in the database. The scanner initiates a baseline scan which is then compared to a fuzzing scanner for each parameter. Each time the length of overflow is extented up until 40 characters.")

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        #print ("................raising issue................")
        rra = [self._httpService]
        return rra

    def getHttpService(self):
        return self._httpService.getHttpService()
