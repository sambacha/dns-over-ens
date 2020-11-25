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

const addrs = {
  ensRegistry: {
    'kovan': ENSRegistryArtifact.networks[42].address,
    'kovan-fork': ENSRegistryArtifact.networks[42].address,
    'live': '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e',
    'live-fork': '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e'
  },
  x509Forest: {
    'kovan': X509ForestOfTrustArtifact.networks[42].address,
    'kovan-fork': X509ForestOfTrustArtifact.networks[42].address,
    // 'live': X509ForestOfTrustArtifact.networks[1].address,
    // 'live-fork': X509ForestOfTrustArtifact.networks[1].address
  }
}

const rootCertDir = {
  'kovan': __dirname + '/FakeLERootX1.pem',
  'kovan-fork': __dirname + '/FakeLERootX1.pem',
  'live': __dirname + '/isrgrootx1.pem',
  'live-fork': __dirname + '/isrgrootx1.pem'
}

const rootEnsNode = {
  'kovan': 'dnsroot.test',
  'kovan-fork': 'dnsroot.test',
  'live': 'dnsroot.eth',
  'live-fork': 'dnsroot.eth'
}

module.exports = function(deployer, network, accounts) {
  const rootEnsNodeOwner = {
    'kovan': accounts[0],
    'kovan-fork': accounts[0],
    'live': accounts[0],
    'live-fork': accounts[0]
  }

  if (network === 'kovan' || network === 'kovan-fork'/* || network === 'live' || network === 'live-fork'*/) {
    deployer.deploy(
      DNSRegistrar,
      namehash.hash(rootEnsNode[network]),
      addrs.ensRegistry[network],
      addrs.x509Forest[network],
      91*24*60*60,
      1
    )
    deployer.then(() => {
      const pemCert = fs.readFileSync(rootCertDir[network]);
      const certBytes = '0x' + forge.asn1.toDer(forge.pki.certificateToAsn1(forge.pki.certificateFromPem(pemCert))).toHex()
      const pubKeyBytes = '0x' + forge.asn1.toDer(forge.pki.publicKeyToAsn1(forge.pki.certificateFromPem(pemCert).publicKey)).toHex();
      const certId = web3.utils.sha3(pubKeyBytes);
      // Set DNSRegistrar as owner of 'dnsroot.test'

      return ENSRegistry.at(addrs.ensRegistry[network])
      .then(registry => {
        // If we're on kovan and we don't own the root domain, register ownership of it
        return Promise.resolve().then(() => {
          if (network === 'kovan') {
            return registry.owner(namehash.hash(rootEnsNode[network]))
            .then(owner => {
              if (owner !== rootEnsNodeOwner[network]) {
                return FIFSRegistrar.at(FIFSRegistrarArtifact.networks[42].address)
                .then(testRegistrar => testRegistrar.register(web3.utils.sha3('dnsroot'), rootEnsNodeOwner[network]))
              }
            })
          }
        })
        // set contract as operator of root node
        .then(() => {
          console.log("setting contract as operator of root node... if you've done this before be sure to un-set the last deployed contract")
          return registry.setApprovalForAll(DNSRegistrar.address, true)
        })
      })
      .then(() => console.log('making root certificate a trust anchor...'))
      .then(() => DNSRegistrar.deployed())
      .then(instance => instance.addTrustAnchor(certId))
    })
  }
};
