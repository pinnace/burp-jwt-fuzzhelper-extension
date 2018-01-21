from burp import IBurpExtender
from burp import IIntruderPayloadProcessor
from burp import ITab
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;

from java.awt import BorderLayout;
from java.awt import GridBagLayout;
from java.awt import GridBagConstraints;
from java.awt import Insets;
from java.awt import Font;
from java.awt import Dimension;
from javax.swing import JScrollPane;
from javax.swing import ImageIcon;
from javax.swing import JFrame;
from javax.swing import JLabel;
from javax.swing import JButton;
from javax.swing import JPanel;
from javax.swing import JComboBox;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing import JTextField;
from javax.swing import JTextArea;
from javax.swing.table import AbstractTableModel;
import jwt

class BurpExtender(IBurpExtender, IIntruderPayloadProcessor, ITab):
    def registerExtenderCallbacks( self, callbacks):
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("JWT Fuzzer")
        callbacks.registerIntruderPayloadProcessor(self)
        
        # Configuration panel Layout
        self._configurationPanel = JPanel()
        gridBagLayout = GridBagLayout()
        gridBagLayout.columnWidths = [ 0, 0, 0, 0 ]
        gridBagLayout.rowHeights = [ 10, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ]
        gridBagLayout.columnWeights = [ 0.0, 0.0, 0.0, 0.0000000000000001 ]
        gridBagLayout.rowWeights = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0000000000000001 ]
        self._configurationPanel.setLayout(gridBagLayout)

        # Help Panel
        self._helpPanel = JPanel()
        # Setup tabs
        self._tabs = JTabbedPane()
        self._tabs.addTab('Configuration',self._configurationPanel)
        self._tabs.addTab('Help',self._helpPanel)

        # Target Options
        comboBoxLabel = JLabel('Target Selection:  ')
        comboBoxLabel.setFont(Font("Tahoma",Font.BOLD, 12))
        c = GridBagConstraints()
        c.gridx = 0
        c.gridy = 1
        c.insets = Insets(0,10,0,0)
        self._configurationPanel.add(comboBoxLabel,c)

        options = [ 'Header', 'Payload' ]
        comboBox = JComboBox(options)
        c = GridBagConstraints()
        c.gridx = 1
        c.gridy = 1
        self._configurationPanel.add(comboBox,c)


        # Selector
        selectorLabel = JLabel("JWT Selector (Required): ")

        # Encryption Key field settings
        """
        textfield1 = JTextField('',50)
        textarea = JTextArea()
        scrollPane = JScrollPane(textarea,JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED)
        scrollPane.setPreferredSize(Dimension(50,50))
        
        encKeyLabel = JLabel('Encryption Key')
        encKeyLabel.setFont(Font("Tahoma",Font.BOLD, 12))

        c = GridBagConstraints()
        c.gridx = 0
        c.gridy = 0
        c.insets = Insets(10,10,20,20)

        self._panel.add(encKeyLabel,c)



        c = GridBagConstraints()
        c.gridy = 1
        c.ipady = 40
        c.gridwidth = 3
        c.fill = GridBagConstraints.HORIZONTAL
        self._panel.add(textarea,c)
        """

        
        callbacks.customizeUiComponent(self._configurationPanel)
        callbacks.customizeUiComponent(self._helpPanel)
        callbacks.customizeUiComponent(self._tabs)
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

    #-----------------------
    # Implement ITab
    #-----------------------

    def getTabCaption(self):
        return "JWT Fuzzer"

    def getUiComponent(self):
        #return self._panel
        return self._tabs




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
