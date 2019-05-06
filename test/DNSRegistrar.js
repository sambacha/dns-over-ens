let DNSRegistrar = artifacts.require("DNSRegistrar")
let MockX509Forest = artifacts.require("./mocks/MockX509ForestOfTrust.sol")
let MockENSRegistry = artifacts.require("./mocks/MockENSRegistry.sol")
var namehash = require('eth-ens-namehash')

contract('DNSRegistrar', (accounts) => {
  beforeEach(async () => {
    this.ens = await MockENSRegistry.new()
    this.x509 = await MockX509Forest.new(namehash.hash('website.org'), namehash.hash('authority.com'), web3.utils.sha3('pretendThisIsAKey'))
    this.registrar = await DNSRegistrar.new(namehash.hash("dnsroot.eth"), this.ens.address, this.x509.address)
    await this.ens.setSubnodeOwner("0x", web3.utils.sha3('eth'), accounts[0])
    await this.ens.setSubnodeOwner(namehash.hash('eth'), web3.utils.sha3('dnsroot'), this.registrar.address)
  })

  it("should register an address as owner of website.org.dnsroot.eth", async () => {
    await this.registrar.addTrustAnchor(web3.utils.sha3('pretendThisIsAKey'))
    const result = await this.registrar.register(web3.utils.sha3('org'), web3.utils.sha3('website'), "0x2222222222222222222222222222222222222222")

    console.log("      gas: register(): " + result.receipt.gasUsed)

    assert.equal(await this.ens.owner(namehash.hash("website.org.dnsroot.eth")), "0x2222222222222222222222222222222222222222", "Didn't add owner")
  })

  it("should fail to register as owner of website.org.dnsroot.eth", async () => {
    try {
      await this.registrar.register(web3.utils.sha3('org'), web3.utils.sha3('website'), "0x2222222222222222222222222222222222222222")
      assert.isTrue(false, "It should've reverted")
    } catch {}
  })
})
