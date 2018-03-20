# burp-jwt-extension

## Comparison

There are a few other very good JWT extensions for Burp Suite. The [JOSEPH](https://github.com/portswigger/json-web-token-attacker) and [JSON Web Tokens](https://github.com/portswigger/json-web-tokens) are two from Portswigger that automate some common attacks and provide highlighting and custom views for JWTs. But they do not provide Intruder payload processors for more targeted fuzzing, which is what this extension aims to do. This is not intended as a replacement for those extensions. In fact, this extension plays very well with the aforementioned tools and I recommend you install them alongside this one.

## Dependencies

This extension requires you to have Jython installed.

The HS* class of signature algorithms (ie. HS256, HS384, and HS512) are implemented using native Python libraries. The RS* and PS* class of signatures are generated via the [pyjwt](https://pyjwt.readthedocs.io/en/latest/) library. Since pyjwt relies on Python `cryptography` libs and these libs cannot be installed via Jython, you will need to specify a folder for loading native Python modules in Extender -> Options -> Python Environment. 

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

1. You must **disable** payload encoding for the `.` character in Intruder options, or they will be URL encoded.

![payload_encoding](https://github.com/cle0patra/burp-jwt-extension-images/blob/master/payload_encoding.png)

## Configuring the fuzzer options

This fuzzer uses [jq's Object Identifier-Index](https://stedolan.github.io/jq/manual/#Basicfilters) to select fields for fuzzing.

#### Example: Fuzzing `alg`

If you wanted to fuzz the `alg` field, you would use "Header" for your target selection and `.alg` as your selector

![alg_selector](https://github.com/cle0patra/burp-jwt-extension-images/blob/master/alg_selector.png)

#### Example: Fuzzing nested claims

Say you want to fuzz the _role_ claim in the following claim. You would use `.user.role` as your selector.

```json
"user" : { 
       "username" : "john.doe", 
       "role" : "admin" 
    } 
```

## Fuzzing examples

### Example 3: `kid` claim fuzzing

[Bitcoin CTF](https://bitcoinctf.com) had a challenge last year involving an improperly handled `kid` field. Here's how this extension could help you attack that.

Looking at [RFC7515](https://tools.ietf.org/html/rfc7515#section-4.1.4), we can see that the `kid` (key id) value is an optional claim field in the header section of a JWT token providing a 'hint' to the operator as to which key was used to sign the token. This is useful if multiple keys are used. Implementation itself is unspecified and up to the operator. Since the `kid` parameter may, and often is, parsed before verifying the signature and implementation itself is up to the operator, this field presents a possible attack vector.

In the Bitcoin CTF, the `kid` field turned out to be a filename under control of the user. By specifying a CSS or JS file with known contents and manipulating the algorithm, they could generate a valid token. To test this with this fuzzer, one could do the following:

To exploit this using the fuzzer you would do the following:

1. Select the **Header** as your target and `.kid` as your selector
2. Set **Generate Signature?** to "True"
3. Select the signature algorithm, in this case HS256
4. Dump the known file contents into the **Signing Key** text field
5. Hit save

![kid_config](https://github.com/cle0patra/burp-jwt-extension-images/blob/master/kid_config.png) 

6. Add your fuzz list

![kid_payload](https://github.com/cle0patra/burp-jwt-extension-images/blob/master/kid_payload.png) 

7. Run Intruder
8. Victory dance

## Tips and limitations

### Tip: `\n`

If you find you are not getting expected results, try appending a line break character, `\n`, to your key (i.e. hit enter).

### Limitations

This fuzzer only handles one field at a time. Future iterations may include support for multiple fields.
