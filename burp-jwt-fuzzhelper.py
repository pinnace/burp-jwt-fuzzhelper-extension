from burp import IBurpExtender
from burp import IIntruderPayloadProcessor
from burp import ITab
from burp import IBurpExtenderCallbacks
from burp import IExtensionStateListener


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
from java.awt import Cursor;
from java.awt.event import MouseAdapter;
from javax.swing import BoxLayout;
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
from javax.swing.border import EmptyBorder;
import jwt
import hashlib
import hmac
import md5
import base64
import re
import rsa
import json
import time
import pyasn1
import webbrowser
from collections import OrderedDict
from jwt.utils import *

# Insets: https://docs.oracle.com/javase/7/docs/api/java/awt/Insets.html


class BurpExtender(IBurpExtender, IBurpExtenderCallbacks, IIntruderPayloadProcessor, ITab, IExtensionStateListener):
    def registerExtenderCallbacks( self, callbacks):
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("JWT Fuzzer")
        callbacks.registerIntruderPayloadProcessor(self)
        callbacks.registerExtensionStateListener(self)
        
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
        gridBagLayout.rowHeights = [ 10, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ]
        gridBagLayout.columnWeights = [ 0.0, 0.0, 0.0 ]
        gridBagLayout.rowWeights = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0]
        self._configurationPanel.setLayout(gridBagLayout)

        # Help Panel
        gridBagLayout = GridBagLayout()
        gridBagLayout.columnWidths = [ 0, 0 ]
        gridBagLayout.rowHeights = [ 10, 10 ]
        gridBagLayout.columnWeights = [ 0.0, 0 ]
        gridBagLayout.rowWeights = [0.0, 0 ]
        """
        #self._helpPanel = JPanel(BorderLayout())
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
        #self._helpPanel.add(topLabel,BorderLayout.PAGE_START)

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
        """

        
        # Setup tabs
        self._tabs = JTabbedPane()
        self._tabs.addTab('Configuration',self._configurationPanel)
        #self._tabs.addTab('Help',self._helpPanel)

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
        self._selectorLabel = JLabel("JSON Selector [Object Identifier-Index Syntax] (Required): ")
        self._selectorLabel.setFont(Font("Tahoma",Font.BOLD, 12))
        c = GridBagConstraints()
        c.gridx = 0
        c.gridy = 2
        c.insets = Insets(0,10,0,0)
        c.anchor = GridBagConstraints.LINE_END
        self._configurationPanel.add(self._selectorLabel, c)

        self._selectorTextField = JTextField('',50)
        c = GridBagConstraints()
        c.gridx = 1
        c.gridy = 2
        self._configurationPanel.add(self._selectorTextField, c)

        # Regex option

        self._regexLabel = JLabel("Use regex as JSON Selector? (Optional): ")
        self._regexLabel.setFont(Font("Tahoma",Font.BOLD, 12))
        c = GridBagConstraints()
        c.gridx = 0
        c.gridy = 3
        c.insets = Insets(0,0,0,0)
        c.anchor = GridBagConstraints.LINE_END
        self._configurationPanel.add(self._regexLabel,c)

        self._regexCheckBox = JCheckBox("", actionPerformed=self.regexSelector)
        c = GridBagConstraints()
        c.gridx = 1
        c.gridy = 3
        c.anchor = GridBagConstraints.FIRST_LINE_START
        self._configurationPanel.add(self._regexCheckBox,c)

        # Signature Options
        generateSignatureLabel = JLabel("Generate signature? (Required): ")
        generateSignatureLabel.setFont(Font("Tahoma",Font.BOLD, 12))
        c = GridBagConstraints()
        c.gridx = 0
        c.gridy = 4
        c.insets = Insets(0,10,0,0)
        c.anchor = GridBagConstraints.LINE_END
        self._configurationPanel.add(generateSignatureLabel,c)

        options = ["False", "True"]
        self._generateSignatureComboBox = JComboBox(options)
        c = GridBagConstraints()
        c.gridx = 1
        c.gridy = 4
        c.anchor = GridBagConstraints.LINE_START
        self._configurationPanel.add(self._generateSignatureComboBox,c)

        signatureAlgorithmLabel = JLabel("Signature Algorithm (Optional): ")
        signatureAlgorithmLabel.setFont(Font("Tahoma",Font.BOLD, 12))
        c = GridBagConstraints()
        c.gridx = 0
        c.gridy = 5
        c.insets = Insets(0,10,0,0)
        c.anchor = GridBagConstraints.LINE_END
        self._configurationPanel.add(signatureAlgorithmLabel,c)

        options = ["None", "HS256","HS384","HS512","ES256","ES384","ES512","RS256","RS384","RS512","PS256","PS256","PS384","PS512"]
        self._algorithmSelectionComboBox = JComboBox(options)
        c = GridBagConstraints()
        c.gridx = 1
        c.gridy = 5
        c.anchor = GridBagConstraints.LINE_START
        self._configurationPanel.add(self._algorithmSelectionComboBox,c)

        # Signing key options
        self._signingKeyLabel = JLabel("Signing Key (Optional): ")
        self._signingKeyLabel.setFont(Font("Tahoma",Font.BOLD, 12))
        c = GridBagConstraints()
        c.gridx = 0
        c.gridy = 6
        c.insets = Insets(0,10,0,0)
        c.anchor = GridBagConstraints.LINE_END
        self._configurationPanel.add(self._signingKeyLabel,c)

        self.addSigningKeyTextArea()
        self._fromFileTextField = JTextField('',50) 

        fromFileLabel = JLabel("Signing key from file? (Optional): ")
        fromFileLabel.setFont(Font("Tahoma",Font.BOLD, 12))
        c = GridBagConstraints()
        c.gridx = 0
        c.gridy = 7
        c.insets = Insets(0,0,0,0)
        c.anchor = GridBagConstraints.LINE_END
        self._configurationPanel.add(fromFileLabel,c)

        self._fromFileCheckBox = JCheckBox("", actionPerformed=self.fromFile)
        c = GridBagConstraints()
        c.gridx = 1
        c.gridy = 7
        c.anchor = GridBagConstraints.FIRST_LINE_START
        self._configurationPanel.add(self._fromFileCheckBox,c)

        self._saveButton = JButton("Save Configuration", actionPerformed=self.saveOptions)
        self._saveButton.setText("Save Configuration")
        c = GridBagConstraints()
        c.gridx = 1
        c.gridy = 8
        c.anchor = GridBagConstraints.FIRST_LINE_START
        self._configurationPanel.add(self._saveButton,c)

        
        callbacks.customizeUiComponent(self._configurationPanel)
        callbacks.customizeUiComponent(self._tabs)
        callbacks.addSuiteTab(self)
        print "Loaded successfully"
        return


    def getProcessorName(self):
        return "JWT Fuzzer"

    def extensionUnloaded(self):
        del self._configurationPanel
        return

    # Intruder logic function
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
                            self._helpers.base64Decode(payload+"=" * (-len(payload) % 4))
                        )

        # Decode header and payload, preserving order if they are JSON objects

        # Decode header
        try:
            header_dict = json.loads(decoded_header, object_pairs_hook=OrderedDict)
        except ValueError:
            print "Failed to decode header!"
            return
        except Exception as e:
            print "Exception: ",e.message

        # Decode payload
        # Payload does not have to be a JSON object.
        #   Ref: https://github.com/auth0/node-jsonwebtoken#usage
        payload_is_string = False
        try:
            payload_dict = json.loads(decoded_payload, object_pairs_hook=OrderedDict)
        except ValueError:
            payload_is_string = True
            payload_dict = decoded_payload
        except Exception as e:
            print "Exception: ",e.message

        target = header_dict if self._fuzzoptions["target"] == "Header" else payload_dict
        selector = self._fuzzoptions["selector"]

        # If using Object Identifier-Index then retrieve the 
        # value specified by the selector, 
        # if this value does not exist, assume the user
        # wants to add the value that would have been specified
        # by the selector to the dictionary (this behavior will 
        # be noted in the help docs)

        intruderPayload = self._helpers.bytesToString(currentPayload)
        if not self._fuzzoptions["regex"]:
            if selector != [""]:
                try:
                    value = self.getValue(target, selector)
                except Exception:
                    target = self.buildDict(target, selector)

            if not self._isNone(selector) and selector != [""]:
                target = self.setValue(target, selector, intruderPayload)
        
        # Simple match-replace for regex
        if self._fuzzoptions["regex"]:
            target_string = target if payload_is_string else json.dumps(target)
            target_string = re.sub(selector, intruderPayload, target_string)
            target = target_string if payload_is_string else json.loads(target_string, object_pairs_hook=OrderedDict)
            if self._fuzzoptions["target"] == "Payload":
                payload_dict = target

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
        payload = payload_dict if payload_is_string else json.dumps(payload_dict, separators=(",",":"))
        header = self._helpers.base64Encode(header).strip("=")
        payload = self._helpers.base64Encode(payload).strip("=")

        contents = header + "." + payload
        
        key = self._fuzzoptions["key"]
        if self._fuzzoptions["signature"]:
            # pyjwt throws error when using a public key in symmetric alg (for good reason of course),
            # must do natively to support algorithmic sub attacks
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

            # JWT can't sign non-JSON payloads. WTF.
            elif algorithm.startswith("RS") and payload_is_string:
                if algorithm == "RS256":
                    rsa_algorithm = "SHA-256"
                elif algorithm == "RS384":
                    rsa_algorithm = "SHA-384"
                else:
                    rsa_algorithm = "SHA-512"
                privkey = rsa.PrivateKey.load_pkcs1(key)
                signature = rsa.sign(contents,privkey,rsa_algorithm)
                signature = base64.b64encode(signature).encode('utf-8').replace("=", "")
                modified_jwt = contents + "." + signature
                print "RSA sig: ",signature
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
        c.gridy = 6
        c.anchor = GridBagConstraints.LINE_START
        self._configurationPanel.add(self._signingKeyScrollPane,c)

    def addSigningKeyFromFileTextField(self):
        c = GridBagConstraints()
        c.gridx = 1
        c.gridy = 6
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


        # Sanity check selector if it's not a regular expression
        self._fuzzoptions["regex"] = self._regexCheckBox.isSelected()
        if not self._regexCheckBox.isSelected():
            m = re.search("(\.\w+)+",self._fuzzoptions["selector"])
            if self._fuzzoptions["selector"] != "." and (isinstance(m,type(None)) or m.group(0) != self._fuzzoptions["selector"]):
                self._saveButton.setText("Invalid JSON Selector!")
            else:
                self._fuzzoptions["selector"] = self._fuzzoptions["selector"].split(".")[1:]
                print "Selector: ",self._fuzzoptions["selector"]
                self._saveButton.setText("Saved!")
                #self._saveButton.setText("Save Configuration")
        # Sanity check the regular expression
        else:
            try:
                re.compile(self._fuzzoptions["selector"])
                self._saveButton.setText("Saved!")
            except re.error:
                self._saveButton.setText("Invalid Regex!")
        return

    #-------------------------
    # From file options
    #------------------------
    def fromFile(self,event):
        if self._fromFileCheckBox.isSelected():
            self._signingKeyLabel.setText("Path to Signing Key (Optional): ")
            self._configurationPanel.remove(self._signingKeyScrollPane)
            self.addSigningKeyFromFileTextField()
        else:
            self._signingKeyLabel.setText("Signing Key (Optional): ")
            self._configurationPanel.remove(self._fromFileTextField)
            self.addSigningKeyTextArea()
        self._configurationPanel.repaint()
        return

    def regexSelector(self,event):
        if self._regexCheckBox.isSelected():
            self._selectorLabel.setText("JSON Selector [Regex] (Required): ")
        else:
            self._selectorLabel.setText("JSON Selector [Object Identifier-Index Syntax] (Required): ")
        self._configurationPanel.repaint()
        return
    #-------------------------
    # Help popup
    #-------------------------
    def helpMenu(self,event):
        self._helpPopup = JFrame('JWT Fuzzer', size=(550, 450) );
        self._helpPopup.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
        helpPanel = JPanel()
        helpPanel.setPreferredSize(Dimension(550, 450))
        helpPanel.setBorder(EmptyBorder(10, 10, 10, 10))
        helpPanel.setLayout(BoxLayout(helpPanel, BoxLayout.Y_AXIS))
        self._helpPopup.setContentPane(helpPanel)
        helpHeadingText = JLabel("<html><h2>JWT Fuzzer</h2></html>")
        authorText = JLabel("<html><p>@author: Lukas Stephan &lt;pinnace&gt;</p></html>")
        aboutText = JLabel("<html><br /> <p>This extension adds an Intruder payload processor for JWTs.</p></html>")
        repositoryText = JLabel("<html>Documentation and source code:</html>")
        repositoryLink = JLabel("<html>- <a href=\"https://github.com/cle0patra/burp-jwt-extension\">https://github.com/cle0patra/burp-jwt-extension</a></html>")
        licenseText = JLabel("<html><br/><p>JWT Fuzzer uses a GPL 3 license. This license does not apply to the dependency below:<p></html>") 
        dependencyLink = JLabel("<html>- <a href=\"https://github.com/jpadilla/pyjwt/blob/master/LICENSE\">Auth0 pyjwt</a></html>")
        dependencyLink.addMouseListener(ClickListener())
        dependencyLink.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
        repositoryLink.addMouseListener(ClickListener())
        repositoryLink.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
        
        helpPanel.add(helpHeadingText)
        helpPanel.add(authorText)
        helpPanel.add(aboutText)
        helpPanel.add(repositoryText)
        helpPanel.add(repositoryLink)
        helpPanel.add(licenseText)
        helpPanel.add(dependencyLink)

        self._helpPopup.setSize(Dimension(550, 450))
        self._helpPopup.pack()
        self._helpPopup.setLocationRelativeTo(None)
        self._helpPopup.setVisible(True)

class ClickListener(MouseAdapter):
    def mousePressed(self, event):
        print "Mouse pressed"
        labelText = event.source.text
        hrefBeginIndex = labelText.index("href=\"")
        hrefEndIndex = labelText.index("\">")
        link = labelText[hrefBeginIndex+6:hrefEndIndex]
        webbrowser.open(link)

