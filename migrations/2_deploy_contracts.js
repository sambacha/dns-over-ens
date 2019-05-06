const DNSRegistrar = artifacts.require('DNSRegistrar');
const X509ForestOfTrust = require('x509-forest-of-trust/build/contracts/X509ForestOfTrust.json');
const ENS = require('@ensdomains/ens/build/contracts/ENSRegistry.json');
const namehash = require('eth-ens-namehash');

module.exports = function(deployer, network) {
  if (network === 'kovan') {
    deployer.deploy(
      DNSRegistrar,
      namehash.hash('dnsroot.test'),
      ENS.networks[42].address,
      X509ForestOfTrust.networks[42].address,
      { gas: 5000000, overwrite: false }
    );
  }
};
