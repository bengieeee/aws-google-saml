# Deploy script to automate process of release

rm -rf dist

python3 setup.py sdist

twine upload dist/*

rm -rf venv # Just incase it wasn't cleared before

sleep 20 # need to wait for PyPi to be ready with new package

python3 -m venv venv

source venv/bin/activate

pip3 install --no-cache-dir aws-google-saml homebrew-pypi-poet

poet --formula aws-google-saml > aws-google-saml.rb

deactivate

rm -rf venv

# Replace 'virtualenv_create(libexec, "python3")' with nothing
sed -i '' 's/virtualenv_create(libexec, "python3")//g' aws-google-saml.rb

# replace 'Shiny new formula' with 'A user browser driven SAML authentication tool for AWS'
sed -i '' 's/Shiny new formula/A user browser driven SAML authentication tool for AWS/g' aws-google-saml.rb

code aws-google-saml.rb

# Copy and upload to Github
