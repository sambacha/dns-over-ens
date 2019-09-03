#!/usr/bin/env bash

# cp ../x509-forest-of-trust/build/contracts/X509ForestOfTrust.json node_modules/x509-forest-of-trust/build/contracts/X509ForestOfTrust.json
cp -r ../x509-forest-of-trust/build node_modules/x509-forest-of-trust/
# cp ../ens/build/contracts/ENSRegistry.json node_modules/@ensdomains/ens/build/contracts/ENSRegistry.json
# cp ../ens/build/contracts/FIFSRegistrar.json node_modules/@ensdomains/ens/build/contracts/FIFSRegistrar.json
cp -r ../ens/build node_modules/@ensdomains/ens/
