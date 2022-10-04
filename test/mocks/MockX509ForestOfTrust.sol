pragma solidity ^0.5.17;

/*
 * @dev Stores validated X.509 certificate chains in parent pointer trees.
 * @dev The root of each tree is a CA root certificate
 */
contract MockX509ForestOfTrust {
    struct Certificate {
        address owner;
        bytes32 parentId;
        uint256 serialNumber;
        uint40 validNotBefore;
        uint40 validNotAfter;
        bool sxg; // canSignHttpExchanges
        uint40 timestamp;
        bool keyUsagePresent;
        uint16 keyUsage;
    }
    // certId => cert  (certId is keccak256(cert.pubKey))
    mapping(bytes32 => Certificate) public certs;
    // ensNamehash(commonName) => certId  OR  ensNamehash(subjectAltName) => certId
    mapping(bytes32 => bytes32[]) public toCertIds;

    constructor(
        bytes32 websiteNamehash,
        bytes32 authorityNamehash,
        bytes32 authorityCertId
    ) public {
        // Trusted root cert
        certs[authorityCertId] = Certificate(
            0x1111111111111111111111111111111111111111,
            authorityCertId,
            1,
            uint40(now - (94 * 24 * 60 * 60)),
            5000000000,
            false,
            uint40(now - (93 * 24 * 60 * 60)),
            true,
            24
        );
        toCertIds[authorityNamehash].push(authorityCertId);
        // Will make test fail if timestamp isn't checked
        certs[keccak256("\xdd\xdd\xdd")] = Certificate(
            0x5555555555555555555555555555555555555555,
            authorityCertId,
            3,
            uint40(now - (94 * 24 * 60 * 60)),
            5000000000,
            false,
            uint40(now - (92 * 24 * 60 * 60)),
            true,
            320
        );
        toCertIds[websiteNamehash].push(keccak256("\xdd\xdd\xdd"));
        // The leaf cert that we're looking for
        certs[keccak256("\xbb\xbb\xbb")] = Certificate(
            msg.sender,
            authorityCertId,
            2,
            uint40(now - 110000),
            5000000000,
            false,
            uint40(now - 100000),
            true,
            320
        );
        toCertIds[websiteNamehash].push(keccak256("\xbb\xbb\xbb"));
        certs[keccak256("\xcc\xcc\xcc")] = Certificate(
            0x5555555555555555555555555555555555555555,
            keccak256("\xcc\xcc\xcc"),
            3,
            uint40(now - 110000),
            5000000000,
            false,
            uint40(now - 100000),
            true,
            320
        );
        toCertIds[websiteNamehash].push(keccak256("\xcc\xcc\xcc"));

        /* certs[authorityCertId].owner = 0x1111111111111111111111111111111111111111;
    certs[authorityCertId].parentId = authorityCertId;
    certs[authorityCertId].pubKey = "\xaa\xaa\xaa";
    certs[authorityCertId].serialNumber = 1;
    certs[authorityCertId].validNotAfter = 5000000000;
    certs[authorityCertId].sxg = false;

    toCertIds[authorityNamehash].push(authorityCertId);

    certs[keccak256("\xbb\xbb\xbb")].owner = msg.sender;
    certs[keccak256("\xbb\xbb\xbb")].parentId = authorityCertId;
    certs[keccak256("\xbb\xbb\xbb")].pubKey = "\xbb\xbb\xbb";
    certs[keccak256("\xbb\xbb\xbb")].serialNumber = 2;
    certs[keccak256("\xbb\xbb\xbb")].validNotAfter = 5000000000;
    certs[keccak256("\xbb\xbb\xbb")].sxg = false;

    toCertIds[websiteNamehash].push(keccak256("\xbb\xbb\xbb"));

    certs[keccak256("\xcc\xcc\xcc")].owner = 0x5555555555555555555555555555555555555555;
    certs[keccak256("\xcc\xcc\xcc")].parentId = keccak256("\xcc\xcc\xcc");
    certs[keccak256("\xcc\xcc\xcc")].pubKey = "\xcc\xcc\xcc";
    certs[keccak256("\xcc\xcc\xcc")].serialNumber = 3;
    certs[keccak256("\xcc\xcc\xcc")].validNotAfter = 5000000000;
    certs[keccak256("\xcc\xcc\xcc")].sxg = false;

    toCertIds[websiteNamehash].push(keccak256("\xcc\xcc\xcc")); */
    }

    function timestamp(bytes32 certId) external view returns (uint40) {
        return certs[certId].timestamp;
    }

    function rootOf(bytes32 certId) external view returns (bytes32) {
        bytes32 id = certId;
        while (id != certs[id].parentId) {
            id = certs[id].parentId;
        }
        return id;
    }

    function owner(bytes32 certId) external view returns (address) {
        return certs[certId].owner;
    }

    function parentId(bytes32 certId) external view returns (bytes32) {
        return certs[certId].parentId;
    }

    function serialNumber(bytes32 certId) external view returns (uint256) {
        return certs[certId].serialNumber;
    }

    function validNotAfter(bytes32 certId) external view returns (uint40) {
        return certs[certId].validNotAfter;
    }

    function validNotBefore(bytes32 certId) external view returns (uint40) {
        return certs[certId].validNotBefore;
    }

    function keyUsage(bytes32 certId) external view returns (bool, bool[9] memory) {
        uint16 mask = 256;
        bool[9] memory flags;
        uint16 bits = certs[certId].keyUsage;
        bool isPresent = certs[certId].keyUsagePresent;
        if (isPresent) {
            for (uint256 i; i < 9; i++) {
                flags[i] = (bits & mask == mask);
                mask = mask >> 1;
            }
        }
        return (isPresent, flags);
    }

    function extKeyUsageCritical(bytes32 certId) external view returns (bool) {
        return false;
    }

    function unparsedCriticalExtensionPresent(bytes32 certId) external view returns (bool) {
        return false;
    }

    function sxg(bytes32 certId) external view returns (bool) {
        return certs[certId].sxg;
    }

    function toCertIdsLength(bytes32 commonNameHash) external view returns (uint256) {
        return toCertIds[commonNameHash].length;
    }
}
