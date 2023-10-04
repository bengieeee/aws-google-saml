# Google SAML Auth

This is a utility to obtain temporary Amazon Web Services (AWS) Security Token Service (STS) credentials for use on the local Command Line Interface (CLI).

This is an enhancement on the popular [AWS Google Auth](https://github.com/cevoaustralia/aws-google-auth) application, which uses a requests library to authenticate to Google before authenticating to AWS via SAML.

This application works similarly, however bypasses the need to authenticate into Google by using the user's existing Google web browser session to post the SAML assertion used for AWS authentication back to this application via local HTTP callback.

## Getting Started

This project relies on Python (specifically, we've only tested on `Python 3`). Please first install Python3 using Brew

```sh
brew install python
```

You'll then need to configure profiles to use in your `~/.aws/config` file. An example below:

```conf

[profile profile-name]
region = ap-southeast-2
account = 123456789012
google_config.google_idp_id = ABCDE1234
google_config.role_name = production-engineer
google_config.google_sp_id = 000000000000

```

### Running the application

Ready? Start the app with the following command

```sh
python3 google-saml-auth.py --profile profile-name
```

### Administrator Instructions

// TODO: How to setup application in Google SAML Console
