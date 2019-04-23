pragma solidity ^0.5.2;

import "./IDNSRegistrar.sol";
import "@ensdomains/ens/contracts/ENS.sol";
import "x509-forest-of-trust/contracts/X509ForestOfTrust.sol";

/**
 * @title A registrar that allocates subdomains to their DNS owners.
 * @author Jonah Groendal
 */
contract DNSRegistrar is IDNSRegistrar {
    ENS ens;
    bytes32 rootNode;
    address admin;
    X509ForestOfTrust x509;
    // certId => isTrusted
    mapping(bytes32 => bool) isTrustedCert;

    modifier only_cert_owner(bytes32 tld, bytes32 domain) {
        // namehash of domain.tld
        bytes32 node = keccak256(abi.encodePacked(keccak256(abi.encodePacked(bytes32(0), tld)), domain));
        require(certOwner(node) == msg.sender);
        _;
    }
    modifier only_admin() {
        require(admin == msg.sender);
        _;
    }

    /**
     * Constructor.
     * @param _ens The address of the ENS registry.
     * @param _rootNode The node that this registrar administers.
     * @param _x509 The address of X509ForestOfTrust, a data structre of validated certs.
     */
    constructor(address _ens, bytes32 _rootNode, address _x509) public {
        ens = ENS(_ens);
        x509 = X509ForestOfTrust(_x509);
        rootNode = _rootNode;
        admin = msg.sender;
    }

    /**
     * @dev Register a web2 domain that you have proven ownership of in X509ForestOfTrust.
     * @param tld The hash of the top-level label of the domain (e.g. "org").
     * @param domain The hash of the second-level label of the domain (e.g. "wikipedia")
     * @param owner The address of the new owner.
     */
    function register(bytes32 tld, bytes32 domain, address owner) external only_cert_owner(tld, domain) {
        bytes32 tldNode = keccak256(abi.encodePacked(rootNode, tld));
        if (ens.owner(tldNode) != address(this))
          ens.setSubnodeOwner(rootNode, tld, address(this));
        ens.setSubnodeOwner(tldNode, domain, owner);
    }

    /**
     * @return The address of the X509ForestOfTrust contract
     */
    function x509ForestOfTrustAddr() external view returns (address) {
      return address(x509);
    }

    /**
     * @dev Gets the owner of the most recently added valid cert that's signed
     * @dev by a trusted and valid root or intermediate cert.
     * @param node The namehash of a DNS domain name
     */
    function certOwner(bytes32 node) internal view returns (address) {
        uint len = x509.toCertIdsLength(node);
        bytes32 certId; bytes32 rootId;
        for (uint i; i<len; i++) {
            certId = x509.toCertIds(node, len-i-1);
            rootId = x509.rootOf(certId);
            if (isTrustedCert[rootId]
                && now < x509.validNotAfter(rootId)
                && now < x509.validNotAfter(certId))
            {
                return x509.owner(certId);
            }
        }
        return address(0);
    }

    /**
     * @dev Add a trusted root cert (from a trustworthy certificate authority)
     * @param certId The keccak256 hash of the cert's public key
     */
    function addTrustAnchor(bytes32 certId) external only_admin {
        emit TrustAnchorAdded(certId);
        isTrustedCert[certId] = true;
    }

    /**
     * @dev Remove a trusted root cert
     * @param certId The keccak256 hash of the cert's public key
     */
    function removeTrustAnchor(bytes32 certId) external only_admin {
        emit TrustAnchorRemoved(certId);
        isTrustedCert[certId] = false;
    }

    /**
     * @dev End this contract's ownership of rootNode
     * @param newOwner The address to transfer ownership to
     */
    function setRootNodeOwner(address newOwner) external only_admin {
        ens.setOwner(rootNode, newOwner);
    }
}
