#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
from threading import Thread

import xml.etree.ElementTree as ET

import webbrowser, base64, botocore.session, boto3, configparser, os, getopt, sys, pkgutil, datetime

boto_session = None

def write_credentials_to_file(options, credentials):
    credentials_parser = configparser.RawConfigParser()
    
    credentials_parser.read(os.path.expanduser(boto_session.get_config_variable('credentials_file')))

    if not credentials_parser.has_section(options.profile):
        credentials_parser.add_section(options.profile)

    credentials_parser.set(options.profile, 'aws_access_key_id', credentials.access_key_id)
    credentials_parser.set(options.profile, 'aws_secret_access_key', credentials.secret_access_key)
    credentials_parser.set(options.profile, 'aws_security_token', credentials.session_token)
    credentials_parser.set(options.profile, 'aws_session_expiration', credentials.session_expiration.strftime('%Y-%m-%dT%H:%M:%S%z'))
    credentials_parser.set(options.profile, 'aws_session_token', credentials.session_token)
    
    with open(os.path.expanduser(boto_session.get_config_variable('credentials_file')), 'w+') as credentials_file:
        credentials_parser.write(credentials_file)

def authenticate_aws(options, saml_assertion):
    role_duration_seconds = None
    
    if options.session_duration and saml_assertion.getSamlAttributeSessionDuration():
        role_duration_seconds = min(saml_assertion.getSamlAttributeSessionDuration(), options.session_duration)
    elif options.session_duration:
        
        role_duration_seconds = options.session_duration
    else:
        role_duration_seconds = saml_assertion.getSamlAttributeSessionDuration()

    sts_call_vars = {
        'RoleArn': options.getAwsRoleArn(),
        'PrincipalArn': saml_assertion.getSamlAttributeRolesMap()[options.getAwsRoleArn()],
        'SAMLAssertion': saml_assertion.getEncodedSamlAssertion(),
        'DurationSeconds': role_duration_seconds
    }

    client = boto3.client('sts', region_name=options.aws_region)
    response = client.assume_role_with_saml(**sts_call_vars)

    return Credentials()\
        .setAccessKeyId(response['Credentials']['AccessKeyId'])\
        .setSecretAccessKey(response['Credentials']['SecretAccessKey'])\
        .setSessionToken(response['Credentials']['SessionToken'])\
        .setSessionExpiration(response['Credentials']['Expiration'])\
        .setSamlAssertion(saml_assertion)

def get_html_page_contents():
    try:
        return pkgutil.get_data(__name__, 'authed.html').decode('utf-8') # Required when packaged
    except:
        with open('aws_google_saml/authed.html') as htmlFile: # Used for local development
            htmlContents = htmlFile.read()
            return htmlContents

def HandlerWrapper(options):
    class CustomHandler(BaseHTTPRequestHandler):
        options = None
        def __init__(self, *args, **kwargs):
             self.options = options
             super(CustomHandler, self).__init__(*args, **kwargs)
        
        def log_message(self, format, *args):
            # This suppresses the default logging of every request to stdout
            return
        
        def do_POST(self):
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode("utf-8")
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            saml_response_encoded = parse_qs(post_data)['SAMLResponse'][0]

            saml_assertion = SamlAssertion().setEncodedSamlAssertion(saml_response_encoded)

            credentials = authenticate_aws(self.options, saml_assertion)

            write_credentials_to_file(self.options, credentials)

            html_page_contents = get_html_page_contents()

            html_page_contents = html_page_contents.replace('__REPLACED_DATE_HERE__', credentials.session_expiration.strftime('%Y-%m-%dT%H:%M:%S%z'))
            html_page_contents = html_page_contents.replace('__REPLACED_PROFILE_NAME_HERE__', self.options.profile)
            
            self.wfile.write(html_page_contents.encode('utf-8'))
            
            exit(0)
    
    return CustomHandler

def start_server(options):
    server_address = ('', options.port)
    HandlerClass = HandlerWrapper(options)

    httpd = HTTPServer(server_address, HandlerClass, options)
    httpd.serve_forever()

class Options:
    profile = None
    google_idp_id = None
    google_sp_id = None
    aws_role_name = None
    aws_region = None
    aws_account_id = None
    
    session_name = None
    session_duration = None
    skip_if_already_authenticated = False

    port = 35002

    def setProfile(self, profile):
        self.profile = profile
        return self
    
    def setGoogleIdpId(self, google_idp_id):
        self.google_idp_id = google_idp_id
        return self
    
    def setGoogleSpId(self, google_sp_id):
        self.google_sp_id = google_sp_id
        return self
    
    def setSkipIfAlreadyAuthenticated(self, skip_if_already_authenticated):
        self.skip_if_already_authenticated = skip_if_already_authenticated
        return self
    
    def setAwsAccountId(self, aws_account_id):
        self.aws_account_id = aws_account_id
        return self

    def setAwsRoleName(self, aws_role_name):
        self.aws_role_name = aws_role_name
        return self
    
    def getAwsRoleArn(self):
        if not self.aws_account_id or not self.aws_role_name:
            raise("Both the AWS Account ID and Role Name must be set to generate the AWS Role ARN")

        return f"arn:aws:iam::{self.aws_account_id}:role/{self.aws_role_name}"

    def setAwsRegion(self, aws_region):
        self.aws_region = aws_region
        return self

    def setPort(self, port):
        self.port = port
        return self
    
    def setSessionName(self, session_name):
        self.session_name = session_name
        return self
    
    def setSessionDuration(self, session_duration):
        self.session_duration = int(session_duration)
        return self
    
    def __str__(self):
        return f"Profile: {self.profile}, Google Idp Id: {self.google_idp_id}, Google Sp Id: {self.google_sp_id}, AWS Role Arn: {self.getAwsRoleArn()}, AWS Region: {self.aws_region}, Port: {self.port}"

class SamlAssertion:
    namespaces = {'saml2p': 'urn:oasis:names:tc:SAML:2.0:protocol', "saml2": "urn:oasis:names:tc:SAML:2.0:assertion"}

    def setEncodedSamlAssertion(self, encoded_saml_assertion):
        self.encoded_saml_assertion = encoded_saml_assertion
        return self
    
    def getEncodedSamlAssertion(self):
        return self.encoded_saml_assertion

    def getDecodedSamlAssertion(self):
        return base64.b64decode(self.encoded_saml_assertion).decode("utf-8")
    
    def getSamlAttributeRolesMap(self):
        samlParts = {}
        samlRolesList = ET.fromstring(self.getDecodedSamlAssertion()).findall(".//saml2:Attribute[@Name='https://aws.amazon.com/SAML/Attributes/Role']/saml2:AttributeValue", self.namespaces)
        
        for samlRole in samlRolesList:
            sessionRoleParts = samlRole.text.split(",")
            samlParts[sessionRoleParts[0]] = sessionRoleParts[1]
        
        return samlParts
    
    def getSamlAttributeRoleSessionName(self):
        return ET.fromstring(self.getDecodedSamlAssertion()).find(".//saml2:Attribute[@Name='https://aws.amazon.com/SAML/Attributes/RoleSessionName']/saml2:AttributeValue", self.namespaces)

    def getSamlAttributeSessionDuration(self):
        return int(ET.fromstring(self.getDecodedSamlAssertion()).find(".//saml2:Attribute[@Name='https://aws.amazon.com/SAML/Attributes/SessionDuration']/saml2:AttributeValue", self.namespaces).text)

class Credentials:
    def setSamlAssertion(self, saml_assertion):
        self.saml_assertion = saml_assertion
        return self

    def setAccessKeyId(self, access_key_id):
        self.access_key_id = access_key_id
        return self
    
    def setSecretAccessKey(self, secret_access_key):
        self.secret_access_key = secret_access_key
        return self
    
    def setSecurityToken(self, security_token):
        self.security_token = security_token
        return self
    
    def setSessionExpiration(self, session_expiration):
        self.session_expiration = session_expiration
        return self
    
    def setSessionToken(self, session_token):
        self.session_token = session_token
        return self

def enrichOptionsFromAwsConfiguration(options):
    config_parser = configparser.RawConfigParser()
    aws_configuration_file_location = boto_session.get_config_variable('config_file')
    config_parser.read(os.path.expanduser(aws_configuration_file_location))
    profile_name = f"profile {options.profile}"
    if not config_parser.has_section(profile_name):
        print(f"Profile '{options.profile}' does not exist in your AWS configuration file.")
        exit()

    try:
        options.setAwsRegion(config_parser.get(profile_name, 'region'))
        options.setAwsAccountId(config_parser.get(profile_name, 'account'))
        options.setGoogleSpId(config_parser.get(profile_name, 'google_config.google_sp_id'))
        options.setGoogleIdpId(config_parser.get(profile_name, 'google_config.google_idp_id'))
        options.setAwsRoleName(config_parser.get(profile_name, 'google_config.role_name'))
    except configparser.NoOptionError as message:
        print(f"Your AWS configuration file (at {aws_configuration_file_location}) is missing some required options.\n\n{message}.\n\nPlease check the README for more information.")
        exit()

    try:
        options.setSessionDuration(config_parser.get(profile_name, 'google_config.duration'))
    except configparser.NoOptionError:
        pass
    
    return options

def isAlreadyAuthenticated(options):
    credentials_parser = configparser.RawConfigParser()
    credentials_parser.read(os.path.expanduser(boto_session.get_config_variable('credentials_file')))

    if credentials_parser.has_section(options.profile):
        if credentials_parser.has_option(options.profile, 'aws_session_expiration'):
            aws_session_expiration = credentials_parser.get(options.profile, 'aws_session_expiration')
            return aws_session_expiration > datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S%z')
        
    return False
                

def enrichOptionsFromArgs(cliArguments, options):
    optionsList, arguments = getopt.getopt(cliArguments,"hp:",["help", "profile=", "port=", "skip-if-authed"])
    for option, argument in optionsList:
        if option == '-h' or option == '--help':
            print ('\nUsage: aws-google-saml.py --profile <profile_name>')
            print ('\nOptions:')
            print ('\t --profile <profile_name> (required)\t\t\t eg: --profile my-profile')
            print ('\t --port <port_number> (optional, default 35002)\t\t eg: --port 35002')
            print ('\t --skip-if-authed (optional, default false)\t\t eg: --skip-if-authed')
            sys.exit()
        if option == '--profile':
            options.setProfile(argument)
        
        if option == '--port':
            options.setPort(argument)
        
        if option == '--skip-if-authed':
            options.setSkipIfAlreadyAuthenticated(True)

    return options

def validateOptions(options):
    validationErrors = []
    
    if options.profile is None:
        validationErrors.append("Please provide a profile name")
    
    if type(options.port) is not int:
        validationErrors.append("Please provide a valid port number")
    
    return validationErrors

def main():
    global boto_session
    options = Options()
    boto_session = botocore.session.Session()

    options = enrichOptionsFromArgs(sys.argv[1:], options)
    options = enrichOptionsFromAwsConfiguration(options)

    validationErrors = validateOptions(options)

    if validationErrors != []:
        for error in validationErrors:
            print(error)

        print("Exiting due to improper usage. Use -h for help.")
        sys.exit()

    if options.skip_if_already_authenticated and isAlreadyAuthenticated(options):
        print(f"You are already authenticated to the {options.profile} profile. Exiting early.")
        sys.exit()
    
    Thread(target=start_server, args=(options,)).start()

    url = f"https://accounts.google.com/o/saml2/initsso?idpid={options.google_idp_id}&spid={options.google_sp_id}&forceauthn=false"
    if os.environ.get('RUNTIME', 'LOCAL') == 'DOCKER':
        print(f"Open the following URL: {url}")
    else:
        webbrowser.open(url)

    # That's it. Now we wait for the HTTP callback


if __name__ == "__main__":
    main()
    