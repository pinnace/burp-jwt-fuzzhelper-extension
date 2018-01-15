from burp import IBurpExtender
from burp import IIntruderPayloadProcessor
from burp import ITab
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;

from java.awt import FlowLayout;
from java.awt import BorderLayout;
from javax.swing import JScrollPane;
from javax.swing import JFrame;
from javax.swing import JLabel;
from javax.swing import JButton;
from javax.swing import JPanel;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing import JTextField;
from javax.swing.table import AbstractTableModel;
import jwt

class BurpExtender(IBurpExtender, IIntruderPayloadProcessor, ITab):
    def registerExtenderCallbacks( self, callbacks):
        self._helpers = callbacks.getHelpers()
        # DEBUG
        #import sys
        #sys.stdout = callbacks.getStdout()
        #sys.stderr = callbacks.getStderr()
        # DEBUG 
        callbacks.setExtensionName("JWT Fuzzer")
        callbacks.registerIntruderPayloadProcessor(self)
       # main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        # table of log entries
        """
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(scrollPane)
        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setRightComponent(tabs)

        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)
        """
        
        textfield1 = JTextField('Type something here',15)
        label = JLabel('Hello from Jython')
        self._panel = JPanel()

        self._panel.setLayout(BorderLayout())
        self._button = JButton("Execute on Proxy History")
        self._panel.add(self._button,BorderLayout.WEST)
        callbacks.customizeUiComponent(self._panel)
        self._panel.add(textfield1,BorderLayout.EAST)
        callbacks.addSuiteTab(self)
        print "test"
        return


    def getProcessorName(self):
        return "JWT Processor"
    def processPayload(self, currentPayload, originalPayload, baseValue):
         dataParameter = self._helpers.bytesToString(
                 #self._helpers.base64Decode(
                     self._helpers.urlDecode(baseValue)
                     )
                 #)
         jwt_components = dataParameter.split(".")
         print "processing"
         print dataParameter
         dataParameter = jwt.decode(dataParameter, verify=False)
         return self._helpers.stringToBytes(
                                 self._helpers.urlEncode(
                                     self._helpers.base64Encode("jhbds")
                                     )
                                 )

    def getTabCaption(self):
        return "JWT Fuzzer"

    def getUiComponent(self):
        return self._panel



class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)

    def changeSelection(self, row, col, toggle, extend):

        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse

        JTable.changeSelection(self, row, col, toggle, extend)
