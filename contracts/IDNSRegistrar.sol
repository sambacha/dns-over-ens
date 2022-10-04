pragma solidity ^0.5.17;

interface IDNSRegistrar {
    event DomainRegistered(bytes32, address);
    event TrustAnchorAdded(bytes32);
    event TrustAnchorRemoved(bytes32);
    event MaxCertAgeSet(uint40);
    event MinNumCertsSet(uint40);

    function register(bytes32 tld, bytes32 domain, address owner) external;
    function isDomainOwner(bytes32 node, address account) external view returns (bool);
    // Administrative methods:
    function addTrustAnchor(bytes32 certId) external;
    function removeTrustAnchor(bytes32 certId) external;
    function setMaxCertAge(uint40 _maxCertAge) external;
    function setMinNumCerts(uint40 _minNumCerts) external;
}
