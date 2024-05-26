# Google SAML Auth

This is a utility to obtain temporary Amazon Web Services (AWS) Security Token Service (STS) credentials for use on the local Command Line Interface (CLI).

This is an enhancement on the popular [AWS Google Auth](https://github.com/cevoaustralia/aws-google-auth) application, which uses a requests library to authenticate to Google before authenticating to AWS via SAML.

This application works similarly, however bypasses the need to authenticate into Google by using the user's existing Google web browser session to post the SAML assertion used for AWS authentication back to this application via local HTTP callback.

## Usage

### AWS Profile configuration

Configure profiles to use in your `~/.aws/config` file. An example below:

```conf

[profile profile-name]
region = ap-southeast-2
account = 123456789012
google_config.google_idp_id = ABCDE1234
google_config.role_name = production-engineer
google_config.google_sp_id = 000000000000

```

### Running the tool - Locally

This project relies on Python (specifically, we've only tested on `Python 3`). Please first install Python3 using Brew

```sh
brew install python
```

Start the app with the following command

```sh
python3 google-saml-auth.py --profile profile-name
```

### Running the tool - Docker

To avoid managing python versions, you can use the Docker image. There are 2 main requirements when running this image:
1. You must map your AWS credentials dir (`~/.aws`) to `/root/.aws` inside the container
2. You must expose the container port `35002` to the port in your machine that you have configured your Google SAML redirect URL (typically 35002, but confirm with your administrator)

With those in mind, you should run the image with something like:

```sh
docker run --rm -it -p 35002:35002 -v ~/.aws:/root/.aws bengieeee/aws-google-saml --profile profile-name
```

This will then print a URL. Open it in your system browser and the container will automatically exit once authentication completes like shown below.

```
$ docker run --rm -it -p 35002:35002 -v ~/.aws:/root/.aws bengieeee/aws-google-saml --profile production-profile
Open the following URL: https://accounts.google.com/o/saml2/initsso?idpid=ThIsIsThEIDPID&spid=123124123123&forceauthn=false
```

### Administrator Instructions

// TODO: How to setup application in Google SAML Console
