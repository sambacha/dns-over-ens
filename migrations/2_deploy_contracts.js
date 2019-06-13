const DNSRegistrar = artifacts.require('DNSRegistrar');
const X509ForestOfTrustArtifact = require('x509-forest-of-trust/build/contracts/X509ForestOfTrust.json');
const ENSArtifact = require('@ensdomains/ens/build/contracts/ENSRegistry.json');
const FIFSRegistrar = artifacts.require('@ensdomains/ens/FIFSRegistrar');
const FIFSRegistrarArtifact = require('@ensdomains/ens/build/contracts/FIFSRegistrar.json');
const namehash = require('eth-ens-namehash');
const fs = require('fs')
const forge = require('node-forge')

module.exports = function(deployer, network) {
  if (network === 'kovan') {
    deployer.deploy(
      DNSRegistrar,
      namehash.hash('dnsroot.test'),
      ENSArtifact.networks[42].address,
      X509ForestOfTrustArtifact.networks[42].address,
      { gas: 5000000, overwrite: false }
    )
    deployer.then(() => {
      const pemCert = fs.readFileSync(__dirname + '/FakeLERootX1.pem');
      const pubKeyBytes = '0x' + forge.asn1.toDer(forge.pki.publicKeyToAsn1(forge.pki.certificateFromPem(pemCert).publicKey)).toHex();
      const certId = web3.utils.sha3(pubKeyBytes);
      // Set DNSRegistrar as owner of 'dnsroot.test'
      return FIFSRegistrar.at(FIFSRegistrarArtifact.networks[42].address)
      .then(testRegistrar => {
        return testRegistrar.register(web3.utils.sha3('dnsroot'), DNSRegistrar.address)
        .catch(error => {}) // already done, dont reject
      })
      // Add LetsEncrypt's staging environment root cert as trust anchor
      .then(() => DNSRegistrar.deployed())
      .then(instance => instance.addTrustAnchor(certId))
    })
  }
};
