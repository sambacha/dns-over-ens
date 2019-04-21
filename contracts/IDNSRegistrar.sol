pragma solidity ^0.5.2;

interface IDNSRegistrar {
    event TrustAnchorAdded(bytes32);
    event TrustAnchorRemoved(bytes32);

    function register(bytes32 tld, bytes32 domain, address owner) external;
    function x509ForestOfTrustAddr() external view returns (address);
    function addTrustAnchor(bytes32 certId) external;
    function removeTrustAnchor(bytes32 certId) external;
    function setRootNodeOwner(address newOwner) external;
}
