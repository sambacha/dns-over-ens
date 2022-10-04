pragma solidity ^0.5.17;

import "./IDNSRegistrar.sol";
import "@ensdomains/ens/contracts/ENSRegistry.sol";
import "x509-forest-of-trust/contracts/X509ForestOfTrust.sol";

/**
 * @title A registrar that allocates subdomains to their DNS owners.
 * @author Jonah Groendal
 */
contract DNSRegistrar is IDNSRegistrar {
    ENSRegistry ens;
    bytes32 rootNode;
    X509ForestOfTrust x509;
    // certId => isTrusted
    mapping(bytes32 => bool) isTrustedCert;
    // A leaf cert must not have been issued more than this number of seconds ago
    uint40 maxCertAge;
    // The Minimum number of certificates an account must hold to be the owner of a domain
    // This is used to decentralize trust and protect against rogue CAs
    // Each cert must be signed by a unique authority
    uint40 minNumCerts;

    modifier only_domain_owner(bytes32 tld, bytes32 domain) {
        // namehash of domain.tld
        bytes32 node = keccak256(
            abi.encodePacked(keccak256(abi.encodePacked(bytes32(0), tld)), domain)
        );
        require(isDomainOwner(node, msg.sender), "Only domain owner");
        _;
    }
    modifier only_root_node_owner() {
        require(ens.owner(rootNode) == msg.sender, "Only root node owner");
        _;
    }

    /**
     * Constructor.
     * @param _ens The address of the ENS registry.
     * @param _rootNode The node that this registrar administers.
     * @param _x509 The address of X509ForestOfTrust, a data structre of validated certs.
     * @param _maxCertAge The max age a valid leaf cert is allowed to be.
     * @param _minNumCerts The min number of certificate authorities.
     */
    constructor(
        bytes32 _rootNode,
        address _ens,
        address _x509,
        uint40 _maxCertAge,
        uint40 _minNumCerts
    ) public {
        rootNode = _rootNode;
        ens = ENSRegistry(_ens);
        x509 = X509ForestOfTrust(_x509);
        maxCertAge = _maxCertAge;
        minNumCerts = _minNumCerts;
    }

    /**
     * @dev Register a web2 domain that you have proven ownership of in X509ForestOfTrust.
     * @param tld The hash of the top-level label of the domain (e.g. "org").
     * @param domain The hash of the second-level label of the domain (e.g. "wikipedia")
     * @param owner The address of the new owner.
     */
    function register(
        bytes32 tld,
        bytes32 domain,
        address owner
    ) external only_domain_owner(tld, domain) {
        bytes32 tldNode = keccak256(abi.encodePacked(rootNode, tld));
        emit DomainRegistered(keccak256(abi.encodePacked(tldNode, domain)), owner);
        if (ens.owner(tldNode) != ens.owner(rootNode))
            ens.setSubnodeOwner(rootNode, tld, ens.owner(rootNode));
        ens.setSubnodeOwner(tldNode, domain, owner);
    }

    /**
     * @param node The ENS namehash of the domain in question. (i.e. namehash("domain.tld"))
     * @param account The address that we are verifying is the domain owner.
     * @return True iff enough certificates for this domain are owned by `account`
     *          and none are owned by any other non-zero address.
     */
    function isDomainOwner(bytes32 node, address account) public view returns (bool) {
        address certOwner;
        bytes32 certId;
        bytes32 rootId;
        bool alreadyCounted;
        bytes32[] memory rootIds = new bytes32[](minNumCerts);
        uint16 rootIdsIndex;
        uint256 len = x509.toCertIdsLength(node);
        uint32 i;
        uint32 j;
        // Loop through all certificates starting with the most recently added.
        for (; i < len; i++) {
            certId = x509.toCertIds(node, len - i - 1);
            // Stop if this cert was added longer ago than the maximum allowed certificate age
            if (block.timestamp - x509.timestamp(certId) > maxCertAge) break;
            if (!isValidCert(certId)) continue;
            rootId = x509.rootOf(certId);
            if (!isTrustedCert[rootId]) continue;
            certOwner = x509.owner(certId);
            if (certOwner == account) {
                if (rootIdsIndex < rootIds.length) {
                    // Certs with the same root cert are only counted once
                    alreadyCounted = false;
                    for (j = 0; j < rootIdsIndex + 1 && !alreadyCounted; j++) {
                        if (rootIds[j] == rootId) alreadyCounted = true;
                    }
                    // Increment certificate count and save its root's id so it doesn't
                    // get re-counted.
                    if (!alreadyCounted) {
                        rootIds[rootIdsIndex] = rootId;
                        rootIdsIndex++;
                    }
                }
            } else if (certOwner != address(0)) {
                // There must be no conflicting certificate owners for a given domain
                return false;
            }
        }

        if (rootIdsIndex >= minNumCerts) return true;
        return false;
    }

    /**
     * @param certId The keccack256 hash of a certificate's DER-encoded public key
     * @return True iff the certificate is valid
     */
    function isValidCert(bytes32 certId) internal view returns (bool) {
        bool keyUsagePresent;
        bool[9] memory keyUsageFlags;
        bytes32 id = certId;
        bytes32 parentId;
        // Must not be expired
        if (!(block.timestamp <= x509.validNotAfter(id))) return false;
        // Must not be older than maxCertAge
        if (!(block.timestamp - x509.validNotBefore(id) <= maxCertAge)) return false;
        (keyUsagePresent, keyUsageFlags) = x509.keyUsage(id);
        // Digital Signature and Key Encipherment required
        if (!(keyUsagePresent && keyUsageFlags[0] && keyUsageFlags[2])) return false;
        // extKeyUsage must not be critical
        if (!(!x509.extKeyUsageCritical(id))) return false;
        // There must be no unparsed critical extensions
        if (!(!x509.unparsedCriticalExtensionPresent(id))) return false;
        // There must be no expired certificates in chain above
        parentId = x509.parentId(id);
        do {
            id = parentId;
            parentId = x509.parentId(id);
            if (!(block.timestamp <= x509.validNotAfter(id))) return false;
        } while (id != parentId);

        return true;
    }

    /**
     * @dev Add a trusted root cert (from a trustworthy certificate authority)
     * @param certId The keccak256 hash of the cert's public key
     */
    function addTrustAnchor(bytes32 certId) external only_root_node_owner {
        emit TrustAnchorAdded(certId);
        isTrustedCert[certId] = true;
    }

    /**
     * @dev Remove a trusted root cert
     * @param certId The keccak256 hash of the cert's public key
     */
    function removeTrustAnchor(bytes32 certId) external only_root_node_owner {
        emit TrustAnchorRemoved(certId);
        isTrustedCert[certId] = false;
    }

    function setMaxCertAge(uint40 _maxCertAge) external only_root_node_owner {
        emit MaxCertAgeSet(_maxCertAge);
        maxCertAge = _maxCertAge;
    }

    function setMinNumCerts(uint40 _minNumCerts) external only_root_node_owner {
        emit MinNumCertsSet(_minNumCerts);
        minNumCerts = _minNumCerts;
    }
}
