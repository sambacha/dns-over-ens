const namehash = require('eth-ens-namehash');
const fs = require('fs');
const forge = require('node-forge');
const X509ForestOfTrustArtifact = require('x509-forest-of-trust/build/contracts/X509ForestOfTrust.json');
const ENSRegistryArtifact = require('@ensdomains/ens/build/contracts/ENSRegistry.json');
const FIFSRegistrarArtifact = require('@ensdomains/ens/build/contracts/FIFSRegistrar.json');
const DNSRegistrar = artifacts.require('DNSRegistrar');
const ENSRegistry = artifacts.require('ENSRegistry');
const FIFSRegistrar = artifacts.require('FIFSRegistrar');
const X509ForestOfTrust = artifacts.require('X509ForestOfTrust');

module.exports = function(deployer, network, accounts) {
  if (network === 'kovan') {
    deployer.deploy(
      DNSRegistrar,
      namehash.hash('dnsroot.test'),
      ENSRegistryArtifact.networks[42].address,
      X509ForestOfTrustArtifact.networks[42].address,
      91*24*60*60,
      1,
      { gas: 5000000, overwrite: false }
    )
    deployer.then(() => {
      const pemCert = fs.readFileSync(__dirname + '/FakeLERootX1.pem');
      const certBytes = '0x' + forge.asn1.toDer(forge.pki.certificateToAsn1(forge.pki.certificateFromPem(pemCert))).toHex()
      const pubKeyBytes = '0x' + forge.asn1.toDer(forge.pki.publicKeyToAsn1(forge.pki.certificateFromPem(pemCert).publicKey)).toHex();
      const certId = web3.utils.sha3(pubKeyBytes);
      // Set DNSRegistrar as owner of 'dnsroot.test'
      console.log('setting contract as owner of root node...')
      return FIFSRegistrar.at(FIFSRegistrarArtifact.networks[42].address)
      .then(testRegistrar => testRegistrar.register(web3.utils.sha3('dnsroot'), DNSRegistrar.address))
      // .then(testRegistrar => {
      //   return ENSRegistry.at(ENSRegistryArtifact.networks[42].address)
      //   // Reset owner to 0x0
      //   .then(ens => {
      //     return ens.owner(namehash.hash('test'))
      //     .then(addr => {
      //       // Temporarily set 'test' node owner to 0 address
      //       return ens.setSubnodeOwner('0x0', web3.utils.sha3('test'), accounts[0])
      //       // so we can reset 'dnsroot.test' node owner to 0 address
      //       .then(() => ens.setSubnodeOwner(namehash.hash('test'), web3.utils.sha3('dnsroot'), '0x0000000000000000000000000000000000000000'))
      //       // then return ownership of 'test' node to FIFSRegistrar
      //       .then(() => ens.setSubnodeOwner('0x0', web3.utils.sha3('test'), addr))
      //     })
      //   })
      //   // Set DNSRegistrar as owner
      //   .then(() => testRegistrar.register(web3.utils.sha3('dnsroot'), DNSRegistrar.address))
      // })
      // Add LetsEncrypt's staging environment root certificate as a trust anchor
      .then(() => X509ForestOfTrust.at(X509ForestOfTrustArtifact.networks[42].address))
      .then(x509 => {
        return x509.validNotAfter(web3.utils.sha3(pubKeyBytes))
        .then(validNotAfter => {
          if (parseInt(validNotAfter) === 0) {
            console.log('adding root certificate...');
            return x509.addCert(certBytes, pubKeyBytes);
          }
        })
      })
      .then(() => console.log('making root certificate a trust anchor...'))
      .then(() => DNSRegistrar.deployed())
      .then(instance => instance.addTrustAnchor(certId))
    })
  }
};
