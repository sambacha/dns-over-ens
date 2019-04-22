pragma solidity  ^0.5.2;

/*
 * @dev Stores validated X.509 certificate chains in parent pointer trees.
 * @dev The root of each tree is a CA root certificate
 */
contract MockX509ForestOfTrust {
  struct Certificate {
    address owner;
    bytes32 parentId;
    bytes pubKey;
    uint serialNumber;
    uint validNotAfter;
    bool cshx; // canSignHttpExchanges
  }
  // certId => cert  (certId is keccak256(cert.pubKey))
  mapping (bytes32 => Certificate) public certs;
  // ensNamehash(commonName) => certId  OR  ensNamehash(subjectAltName) => certId
  mapping (bytes32 => bytes32[]) public toCertIds;

  constructor(bytes32 websiteNamehash, bytes32 authorityNamehash, bytes32 authorityCertId) public {
    certs[authorityCertId] = Certificate(0x1111111111111111111111111111111111111111, authorityCertId, "\xaa\xaa\xaa", 1, 5000000000, false);
    toCertIds[authorityNamehash].push(authorityCertId);
    certs[keccak256("\xbb\xbb\xbb")] = Certificate(msg.sender, authorityCertId, "\xbb\xbb\xbb", 2, 5000000000, false);
    toCertIds[websiteNamehash].push(keccak256("\xbb\xbb\xbb"));
    certs[keccak256("\xcc\xcc\xcc")] = Certificate(0x5555555555555555555555555555555555555555, keccak256("\xcc\xcc\xcc"), "\xcc\xcc\xcc", 3, 5000000000, false);
    toCertIds[websiteNamehash].push(keccak256("\xcc\xcc\xcc"));
  }

  function rootOf(bytes32 certId)
  external view returns (bytes32)
  {
    bytes32 id = certId;
    while (id != certs[id].parentId) {
      id = certs[id].parentId;
    }
    return id;
  }

  function owner(bytes32 certId)
  external view returns (address)
  {
    return certs[certId].owner;
  }

  function parentId(bytes32 certId)
  external view returns (bytes32)
  {
    return certs[certId].parentId;
  }

  function pubKey(bytes32 certId)
  external view returns (bytes memory)
  {
    return certs[certId].pubKey;
  }

  function serialNumber(bytes32 certId)
  external view returns (uint)
  {
    return certs[certId].serialNumber;
  }

  function validNotAfter(bytes32 certId)
  external view returns (uint)
  {
    return certs[certId].validNotAfter;
  }

  function cshx(bytes32 certId)
  external view returns (bool)
  {
    return certs[certId].cshx;
  }

  function toCertIdsLength(bytes32 commonNameHash)
  external view returns (uint)
  {
    return toCertIds[commonNameHash].length;
  }
}
