from burp import IBurpExtender
from burp import IIntruderPayloadProcessor
from burp import ITab
from burp import IBurpExtenderCallbacks


from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;

from java.awt import BorderLayout;
from java.awt import GridBagLayout;
from java.awt import GridBagConstraints;
from java.awt import Insets;
from java.awt import Font;
from javax.swing import JScrollPane;
from javax.swing import JLabel;
from javax.swing import JButton;
from javax.swing import JCheckBox;
from javax.swing import JPanel;
from javax.swing import JComboBox;
from javax.swing import JTabbedPane;
from javax.swing import SwingUtilities;
from javax.swing import JTextField;
from javax.swing import JTextArea;
from javax.swing import JFrame;
import jwt
import hashlib
import hmac
import md5
import base64
import re
import json
import time
from collections import OrderedDict
from jwt.utils import *

# Insets: https://docs.oracle.com/javase/7/docs/api/java/awt/Insets.html


class BurpExtender(IBurpExtender, IBurpExtenderCallbacks, IIntruderPayloadProcessor, ITab):
    def registerExtenderCallbacks( self, callbacks):
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("JWT Fuzzer")
        callbacks.registerIntruderPayloadProcessor(self)
        
        self._fuzzoptions = { 
                                "target" : "Header", 
                                "selector" : None, 
                                "signature" : False,
                                "algorithm" : "HS256",
                                "key" : ""
                            }

        self._isNone = lambda val: isinstance(val, type(None))

        # Configuration panel Layout
        self._configurationPanel = JPanel()
        gridBagLayout = GridBagLayout()
        gridBagLayout.columnWidths = [ 0, 0, 0]
        gridBagLayout.rowHeights = [ 10, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ]
        gridBagLayout.columnWeights = [ 0.0, 0.0, 0.0 ]
        gridBagLayout.rowWeights = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0]
        self._configurationPanel.setLayout(gridBagLayout)

        # Help Panel
        gridBagLayout = GridBagLayout()
        gridBagLayout.columnWidths = [ 0, 0 ]
        gridBagLayout.rowHeights = [ 10, 10 ]
        gridBagLayout.columnWeights = [ 0.0, 0 ]
        gridBagLayout.rowWeights = [0.0, 0 ]
        self._helpPanel = JPanel(BorderLayout())
        topLabel = JLabel()
        topLabel.setFont(Font("Lucida Grande", Font.BOLD, 18))
        #topLabel.setText("JWT Fuzzer usage:")
        topLabel.setText(helpText)

        c = GridBagConstraints()
        c.anchor = GridBagConstraints.FIRST_LINE_START
        c.fill = GridBagConstraints.NONE
        c.gridx = 0
        c.gridy = 0
        c.insets = Insets(0,10,0,10)
        self._helpPanel.add(topLabel,BorderLayout.PAGE_START)

        targetHelpHeaderLabel = JLabel()
        targetHelpHeaderLabel.setFont(Font("Lucida Grande", Font.BOLD, 14))
        targetHelpHeaderLabel.setText("Target Selection:")
        c = GridBagConstraints()
        c.anchor = GridBagConstraints.FIRST_LINE_START
        c.gridx = 0
        c.gridy = 1
        c.insets = Insets(0,10,0,10)
        #self._helpPanel.add(targetHelpHeaderLabel,BorderLayout.LINE_START)

        targetHelpLabel = JLabel()
        targetHelpLabel.setFont(Font("Lucida Grande", Font.PLAIN, 12))
        targetHelpLabel.setText(targetHelpText)
        c = GridBagConstraints()
        c.anchor = GridBagConstraints.FIRST_LINE_START
        c.insets = Insets(0,10,0,10)
        c.gridx = 0
        c.gridy = 2
        #self._helpPanel.add(targetHelpLabel,BorderLayout.PAGE_END)


        # Setup tabs
        self._tabs = JTabbedPane()
        self._tabs.addTab('Configuration',self._configurationPanel)
        self._tabs.addTab('Help',self._helpPanel)

        # Target Options
        targetLabel = JLabel("Target Selection (Required): ")
        targetLabel.setFont(Font("Tahoma",Font.BOLD, 12))
        c = GridBagConstraints()
        c.gridx = 0
        c.gridy = 1
        c.insets = Insets(0,10,0,0)
        c.anchor = GridBagConstraints.LINE_END
        self._configurationPanel.add(targetLabel,c)

        options = [ 'Header', 'Payload' ]
        self._targetComboBox = JComboBox(options)
        c = GridBagConstraints()
        c.gridx = 1
        c.gridy = 1
        c.anchor = GridBagConstraints.LINE_START
        self._configurationPanel.add(self._targetComboBox,c)

        # Help Button
        self._helpButton = JButton("Help", actionPerformed=self.helpMenu)
        c = GridBagConstraints()
        c.gridx = 2
        c.gridy = 1
        c.anchor = GridBagConstraints.FIRST_LINE_START
        self._configurationPanel.add(self._helpButton,c)

        # Selector Options
        selectorLabel = JLabel("JSON Selector (Required): ")
        selectorLabel.setFont(Font("Tahoma",Font.BOLD, 12))
        c = GridBagConstraints()
        c.gridx = 0
        c.gridy = 2
        c.insets = Insets(0,10,0,0)
        c.anchor = GridBagConstraints.LINE_END
        self._configurationPanel.add(selectorLabel, c)

        self._selectorTextField = JTextField('',50)
        c = GridBagConstraints()
        c.gridx = 1
        c.gridy = 2
        self._configurationPanel.add(self._selectorTextField, c)

        # Signature Options
        generateSignatureLabel = JLabel("Generate signature? (Required): ")
        generateSignatureLabel.setFont(Font("Tahoma",Font.BOLD, 12))
        c = GridBagConstraints()
        c.gridx = 0
        c.gridy = 3
        c.insets = Insets(0,10,0,0)
        c.anchor = GridBagConstraints.LINE_END
        self._configurationPanel.add(generateSignatureLabel,c)

        options = ["False", "True"]
        self._generateSignatureComboBox = JComboBox(options)
        c = GridBagConstraints()
        c.gridx = 1
        c.gridy = 3
        c.anchor = GridBagConstraints.LINE_START
        self._configurationPanel.add(self._generateSignatureComboBox,c)

        signatureAlgorithmLabel = JLabel("Signature Algorithm (Optional): ")
        signatureAlgorithmLabel.setFont(Font("Tahoma",Font.BOLD, 12))
        c = GridBagConstraints()
        c.gridx = 0
        c.gridy = 4
        c.insets = Insets(0,10,0,0)
        c.anchor = GridBagConstraints.LINE_END
        self._configurationPanel.add(signatureAlgorithmLabel,c)

        options = ["None", "HS256","HS384","HS512","ES256","ES384","ES512","RS256","RS384","RS512","PS256","PS256","PS384","PS512"]
        self._algorithmSelectionComboBox = JComboBox(options)
        c = GridBagConstraints()
        c.gridx = 1
        c.gridy = 4
        c.anchor = GridBagConstraints.LINE_START
        self._configurationPanel.add(self._algorithmSelectionComboBox,c)

        # Signing key options
        self._signingKeyLabel = JLabel("Signing Key (Optional): ")
        self._signingKeyLabel.setFont(Font("Tahoma",Font.BOLD, 12))
        c = GridBagConstraints()
        c.gridx = 0
        c.gridy = 5
        c.insets = Insets(0,10,0,0)
        c.anchor = GridBagConstraints.LINE_END
        self._configurationPanel.add(self._signingKeyLabel,c)

        self.addSigningKeyTextArea()
        self._fromFileTextField = JTextField('',50) 
        """
        self._signingKeyTextArea = JTextArea()
        self._signingKeyTextArea.setColumns(50)
        self._signingKeyTextArea.setRows(10)
        self._signingKeyScrollPane = JScrollPane(self._signingKeyTextArea)
        c = GridBagConstraints()
        c.gridx = 1
        c.gridy = 5
        c.anchor = GridBagConstraints.LINE_START
        self._configurationPanel.add(self._signingKeyScrollPane,c)
        """
        fromFileLabel = JLabel("Signing key from file? (Optional): ")
        fromFileLabel.setFont(Font("Tahoma",Font.BOLD, 12))
        c = GridBagConstraints()
        c.gridx = 0
        c.gridy = 6
        c.insets = Insets(0,0,0,0)
        c.anchor = GridBagConstraints.NORTH
        self._configurationPanel.add(fromFileLabel,c)

        self._fromFileCheckBox = JCheckBox("", actionPerformed=self.fromFile)
        c = GridBagConstraints()
        c.gridx = 1
        c.gridy = 6
        c.anchor = GridBagConstraints.FIRST_LINE_START
        self._configurationPanel.add(self._fromFileCheckBox,c)

        self._saveButton = JButton("Save Configuration", actionPerformed=self.saveOptions)
        self._saveButton.setText("Save Configuration")
        c = GridBagConstraints()
        c.gridx = 1
        c.gridy = 7
        c.anchor = GridBagConstraints.FIRST_LINE_START
        self._configurationPanel.add(self._saveButton,c)

        
        callbacks.customizeUiComponent(self._configurationPanel)
        callbacks.customizeUiComponent(self._helpPanel)
        callbacks.customizeUiComponent(self._tabs)
        callbacks.addSuiteTab(self)
        print "Loaded successfully"
        return


    def getProcessorName(self):
        return "JWT Fuzzer"
    def processPayload(self, currentPayload, originalPayload, baseValue):
        dataParameter = self._helpers.bytesToString(
                         self._helpers.urlDecode(baseValue)
                       )

        # utf-8 encode
        header,payload,signature = [unicode(s).encode('utf-8') for s in dataParameter.split(".",3)]
        decoded_header = self._helpers.bytesToString(
                            self._helpers.base64Decode(header + "=" * (-len(header) % 4))
                        )
        decoded_payload = self._helpers.bytesToString(
                            self._helpers.base64Decode(payload+"=" * (-len(header) % 4))
                        )
        # Preserve JWT order
        header_dict = json.loads(decoded_header, object_pairs_hook=OrderedDict)
        payload_dict = json.loads(decoded_payload, object_pairs_hook=OrderedDict)
        

        target = header_dict if self._fuzzoptions["target"] == "Header" else payload_dict
        selector = self._fuzzoptions["selector"]

        # Retrieve the value specified by the selector, 
        # if this value does not exist, assume the user
        # wants to add the value that would have been specified
        # by the selector to the dictionary (this behavior will 
        # be noted in the help docs)
        try:
            value = self.getValue(target, selector)
        except Exception:
            target = self.buildDict(target, selector)

        if not self._isNone(selector):
            intruderPayload = self._helpers.bytesToString(currentPayload) 
            target = self.setValue(target, selector, intruderPayload)
        
        

        algorithm = self._fuzzoptions["algorithm"]
        if self._fuzzoptions["signature"]: 
            # pyjwt requires lowercase 'none'. If user wants to try
            # "none", "NonE", "nOnE", etc... they should use .alg
            # as selector, delete sig from intruder and use those
            # permutations as their fuzz list (outlined in help docs)
            # and keep "Generate Signature" as False
            algorithm = "none" if algorithm.lower() == "none" else algorithm
            header_dict["alg"] = algorithm

        header = json.dumps(header_dict, separators=(",",":"))
        payload = json.dumps(payload_dict, separators=(",",":"))
        header = self._helpers.base64Encode(header).strip("=")
        payload = self._helpers.base64Encode(payload).strip("=")

        contents = header + "." + payload
        
        key = self._fuzzoptions["key"]
        if self._fuzzoptions["signature"]:
            # pyjwt throws error when using a public key in symmetric alg (for good reason of course),
            # must do manually
            if algorithm.startswith("HS"):
                if algorithm == "HS256":
                    hmac_algorithm = hashlib.sha256
                elif algorithm == "HS384":
                    hmac_algorithm = hashlib.sha384
                else:
                    hmac_algorithm = hashlib.sha512
            
                print "Using algorithm: ",algorithm
                signature = self._helpers.base64Encode(
                            hmac.new(
                                    key, contents, hmac_algorithm
                                ).digest()
                    ).strip("=")

                modified_jwt = contents + "." +signature
            else:
                # Use pyjwt when using asymmetric alg
                if algorithm == "none":
                    key = ""
                modified_jwt = jwt.encode(payload_dict,key,algorithm=algorithm,headers=header_dict)
        else:
            modified_jwt = contents + "." + signature

        return self._helpers.stringToBytes(modified_jwt)

    
    #-----------------------
    # getValue:
    #   @return: A value at arbitrary depth in dictionary
    #   @throws: TypeError
    #-----------------------
    def getValue(self, dictionary, values):
        return reduce(dict.__getitem__, values, dictionary)

    #-----------------------
    # buildDict:
    #   @note: Will build dictionary of arbitrary depth
    #-----------------------
    def buildDict(self, dictionary, keys):
        if self._isNone(keys):
            return dictionary

        root = current = dictionary
        for key in keys:
            if key not in current:
                current[key] = {}
            current = current[key]
        return root

    #----------------------
    # setValue:
    #   @note: Will set key of arbitrary depth
    #-----------------------
    def setValue(self, dictionary, keys, value):
        root = current = dictionary
        for i,key in enumerate(keys):
            if i == len(keys) - 1:
                current[key] = value
                break
            if key in current:
                current = current[key]
            else:
                # Should never happen
                current = self.buildDict(current, keys)
        return root
    
    #-----------------------
    # addSigningKeyTextArea:
    #   @note: Will toggle if fromFile selected. Be DRY.
    #----------------------
    def addSigningKeyTextArea(self):
        self._signingKeyTextArea = JTextArea()
        self._signingKeyTextArea.setColumns(50)
        self._signingKeyTextArea.setRows(10)
        self._signingKeyScrollPane = JScrollPane(self._signingKeyTextArea)
        c = GridBagConstraints()
        c.gridx = 1
        c.gridy = 5
        c.anchor = GridBagConstraints.LINE_START
        self._configurationPanel.add(self._signingKeyScrollPane,c)

    def addSigningKeyFromFileTextField(self):
        c = GridBagConstraints()
        c.gridx = 1
        c.gridy = 5
        self._configurationPanel.add(self._fromFileTextField, c)
    #-----------------------
    # End Helpers
    #-----------------------

    #-----------------------
    # Implement ITab
    #-----------------------

    def getTabCaption(self):
        return "JWT Fuzzer"

    def getUiComponent(self):
        return self._tabs

    #---------------------------
    # Save configuration options
    #---------------------------

    def saveOptions(self,event):
        print "Saving! "
        self._fuzzoptions["target"]     = self._targetComboBox.getSelectedItem()
        self._fuzzoptions["selector"]   = self._selectorTextField.getText()
        self._fuzzoptions["signature"]  = True if self._generateSignatureComboBox.getSelectedItem() == "True" else False
        self._fuzzoptions["algorithm"]  = self._algorithmSelectionComboBox.getSelectedItem()
        
        if self._fromFileCheckBox.isSelected():
            filename = self._fromFileTextField.getText()
            if os.path.isdir(filename):
                print "{} is a directory".format(filename)
                return
            if os.path.exists(filename):
                with open(filename, 'rb') as f:
                    self._fuzzoptions["key"] = f.read()
        else:
            self._fuzzoptions["key"]    = unicode(self._signingKeyTextArea.getText()).encode("utf-8")
        # RSA keys need to end with a line break. Many headaches because of this.
        if not self._fuzzoptions["key"].endswith("\n") and self._fuzzoptions["algorithm"].startswith("RS"):
            self._fuzzoptions["key"] += "\n"
        print self._fuzzoptions
        # Sanity check selector
        m = re.search("(\.\w+)+",self._fuzzoptions["selector"])
        if isinstance(m,type(None)) or m.group(0) != self._fuzzoptions["selector"]:
            self._saveButton.setText("Invalid JSON Selector!")
        else:
            self._fuzzoptions["selector"] = self._fuzzoptions["selector"].split(".")[1:]
            print "Selector: ",self._fuzzoptions["selector"]
            self._saveButton.setText("Saved!")
            #self._saveButton.setText("Save Configuration")
        return

    #-------------------------
    # From file options
    #------------------------
    def fromFile(self,event):
        if self._fromFileCheckBox.isSelected():
            self._signingKeyLabel.setText("Path to Signing Key (Optional): ")
            self._configurationPanel.remove(self._signingKeyScrollPane)
            self.addSigningKeyFromFileTextField()
            self._configurationPanel.repaint()
        else:
            self._signingKeyLabel.setText("Signing Key (Optional): ")
            self._configurationPanel.remove(self._fromFileTextField)
            self.addSigningKeyTextArea()
            self._configurationPanel.repaint()

    #-------------------------
    # Help popup
    #-------------------------
    def helpMenu(self,event):
        print "Helphelp"
        self._helpPopup = JFrame('JWT Fuzzer help', size=(550, 450) );
        helpHeadingText = JLabel("<html><h2>JWT Fuzzer</h2></html>")

        self._helpPopup.add(helpText)
        self._helpPopup.pack()
        self._helpPopup.setLocationRelativeTo(None)
        self._helpPopup.setVisible(True)
        #self._helpPopup.addText("Some text")
        #addURL
        #addRemoteImage

infoBox = """<html>


</html>"""
helpText = """<html>
<p style="font-size:18px"><b>JWT Fuzzer Help: </b></p><br />
<p style="font-size:14px"><i>Target Selection: </i></p><br />
<p style="font-size:12px">Select which section of the JWT you will be fuzzing.
<br />You can fuzz the <b>"Header"</b> section or the <b>"Payload"</b> section
This will default to the <b>"Header"</b> section</p><br />
<p style="font-size:14px"><i>Selector: </i></p><br />
<p style="font-size:12px">Specify a selector for the value you wish to fuzz. This is done using <a href="https://stedolan.github.io/jq/manual/">jq's Object Identifier-Index</a> syntax. <br />
<i>Example 1: </i> Fuzzing the "alg" value<br /> 
If you wished to fuzz the value of "alg" you would specify </b>Header</b> as your target and use <i>.alg</i> as your selector. <br />
<i>Example 2: </i> Fuzzing nested values <br />
Say you JWT payload had a claim that looked like this: <br />
<i>{</i> <br />
<i>   "user" : { </i> <br />
<i>       "username" : "john.doe", </i> <br />
<i>       "role" : "admin" </i> <br />
<i>    } </i> <br />
<i>}</i><br /><br />
To fuzz the <i>role</i>, your selector would be <i>.user.role</i> and your target would be <b>Payload</b><br />
</html>"""
targetHelpText = """<html><p style="font-size:20px">Selection which section of the JWT will be fuzzed.<br />You can fuzz the <b>"Header"</b> section or the <b>"Payload"</b> section</p></html>"""




