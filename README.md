# burp-jwt-extension

## Dependencies

This extension requires you to have Jython installed.

The HS* class of signature algorithms (ie. HS256, HS384, and HS512) are implemented using native Python libraries. The RS* and PS* class of signatures are generate via the [pyjwt](https://pyjwt.readthedocs.io/en/latest/) library. Since pyjwt relies on Python `cryptography` libs and these libs cannot be installed via Jython, you will need to specify a folder for loading native Python modules in Extender -> Options -> Python Environment. 

## Installation

#### Install Python dependencies

```bash
$ pip install -r requirements.txt
```

#### Install the extension.

You can do this in the extender pane

![install_extension](https://github.com/cle0patra/burp-jwt-extension-images/blob/master/install_extension.png)


## Usage

You can invoke the extension in the Intruder tab by invoking it in the payload processor pane

![payload_processing](https://github.com/cle0patra/burp-jwt-extension-images/blob/master/payload_processing.png)

![payload_processing_rule](https://github.com/cle0patra/burp-jwt-extension-images/blob/master/payload_processing_rule.png)

![processing_rule](https://github.com/cle0patra/burp-jwt-extension-images/blob/master/processing_rule.png)

![invoke_processor](https://github.com/cle0patra/burp-jwt-extension-images/blob/master/invoke_processor.png)

### **Important**

1. You must disable payload encoding for the `.` character in Intruder options, or they will be URL encoded.

![payload_encoding](https://github.com/cle0patra/burp-jwt-extension-images/blob/master/payload_encoding.png)


### Example 3: `kid` parameter fuzzing

Bitcoin CTF had a challenge this year involving an improperly handled `kid` field. 

Looking at [RFC7515](https://tools.ietf.org/html/rfc7515#section-4.1.4), we can see that the `kid` value is an optional claim field in the header section of a JWT token providing a 'hint' to the operator as to which key was used to sign the token. This is useful if multiple keys are used. Implementation itself is unspecified and up to the operator. Since the `kid` parameter may, and often is, parsed before verifying the signature and implementation itself is up to the operator, this field presents a new attack vector.

In the Bitcoin CTF, the `kid` field turned out to be a filename the user could specify. By specifying a CSS or JS file with known contents and manipulating the algorithm, they could generate a valid token. To test this with this fuzzer, one could do the following:
