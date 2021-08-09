from burp import IBurpExtender
from burp import IHttpListener
import json

class BurpExtender(IBurpExtender, IHttpListener):
        
    def	registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("GraphQL Operation Logger")
        
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)

        # bbac is the best
        
        return
                
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):

        if (toolFlag != self._callbacks.TOOL_TARGET and
                toolFlag != self._callbacks.TOOL_PROXY):
            return

        path = self._helpers.analyzeRequest(messageInfo).getUrl().getPath()
        method = self._helpers.analyzeRequest(messageInfo).getMethod()

        if method == 'POST':
            bodyOff = self._helpers.analyzeRequest(messageInfo).getBodyOffset()
            bodyBytes = messageInfo.getRequest()[bodyOff:]
            body = self._helpers.bytesToString(bodyBytes)

            try:
                bodyJson = json.loads(body)

                if str(messageInfo.getComment()) == "None":
                    oldComment = ""
                else:
                    oldComment = " " + messageInfo.getComment()

                messageInfo.setComment(oldComment + bodyJson["operationName"])
                # just in case any other extensions have already set a comment, try to preserve it

                # uncomment this for higlight
                # messageInfo.setHighlight("cyan")
            except:
                pass

