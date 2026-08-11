// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";

/// @notice Minimal views of the deployed MA v2 contracts. Hand-declared rather than importing the
///         modular-account source, whose build pins `evm_version = cancun` — EIP-7702 needs Prague.
interface IModularAccount {
    /// @param validationConfig packed bytes25: [20-byte module][4-byte entityId][1-byte flags]
    function installValidation(
        bytes25 validationConfig,
        bytes4[] calldata selectors,
        bytes calldata installData,
        bytes[] calldata hooks
    ) external;
}

interface IModularAccountRuntime {
    function executeWithRuntimeValidation(bytes calldata data, bytes calldata authorization)
        external
        payable
        returns (bytes memory);
}

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}

interface ISingleSignerValidationModule {
    function replaySafeHash(address account, bytes32 hash) external view returns (bytes32);
    function signers(uint32 entityId, address account) external view returns (address);
}

/// @notice Does Alchemy Modular Account v2 scope a session key's authority to *sign* for the account,
///         or only its authority to execute?
///
///         This is the direct counterpart to the finding in the Uniswap Calibur PoC, where a key
///         scoped by a policy hook to one target and a value cap could still mint arbitrary ERC-1271
///         account signatures (Permit2, Seaport, any off-chain intent) — because Calibur's
///         `isValidSignature` admits any registered key, and the hook was address-flag-mined without
///         the signature-validation bit. Scoping there covers the value-transfer path only.
///
///         ERC-6900 instead makes signing a first-class per-validation flag and requires the account
///         to enforce it: "If the validation function is attempted to be used for signature
///         validation and the flag `isSignatureValidation` is set to false, validation MUST revert."
///         MA v2 implements that in `ModularAccountBase._exec1271Validation`.
///
///         Runs against a pinned Sepolia fork using the canonical deployed contracts. Nothing mocked.
contract MAv2SignatureScopeTest is Test {
    /// @dev Canonical deployments, verified live on Sepolia via accountId()/moduleId().
    address constant SMA_7702 = 0x69007702764179f14F51cdce752f4f775d74E139; // alchemy.sma-7702.1.0.0
    address constant SINGLE_SIGNER = 0x00000000000099DE0BF6fA90dEB851E2A2df7d83; // single-signer-validation.1.0.0

    /// @dev Pinned so the run is deterministic regardless of chain drift.
    uint256 constant FORK_BLOCK = 11_440_000;

    /// @dev ValidationFlags — byte 24 of the packed ValidationConfig (erc6900 ValidationConfigLib).
    uint8 constant FLAG_IS_USER_OP_VALIDATION = 0x01;
    uint8 constant FLAG_IS_SIGNATURE_VALIDATION = 0x02;

    /// @dev isValidSignature layout: [1-byte options][4-byte entityId][segments].
    ///      options: bit0 global, bit1 deferred action, bit2 direct-call.
    uint8 constant OPTS_NONE = 0x00;
    uint8 constant OPTS_GLOBAL = 0x01;

    /// @dev erc6900 RESERVED_VALIDATION_DATA_INDEX — marks the final (validation) signature segment.
    uint8 constant FINAL_SEGMENT = 0xFF;

    /// @dev SingleSignerValidationModule._checkSig / SMA _checkSignature want a type prefix; EOA == 0.
    uint8 constant SIG_TYPE_EOA = 0x00;

    /// @dev The SMA's built-in fallback signer (the EOA itself) is entity id 0.
    uint32 constant FALLBACK_VALIDATION_ID = 0;

    bytes4 constant ERC1271_MAGIC = 0x1626ba7e;

    /// @dev ModularAccountBase.SignatureValidationInvalid(ModuleEntity); ModuleEntity is a bytes24.
    error SignatureValidationInvalid(bytes24 validationFunction);

    // keccak256("EIP712Domain(uint256 chainId,address verifyingContract)")
    bytes32 constant DOMAIN_SEPARATOR_TYPEHASH =
        0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;
    // keccak256("ReplaySafeHash(bytes32 hash)")
    bytes32 constant REPLAY_SAFE_HASH_TYPEHASH =
        0x294a8735843d4afb4f017c76faf3b7731def145ed0025fc9b1d5ce30adf113ff;

    /// @dev The digest a scoped key must not be able to authorize.
    bytes32 constant OFF_CHAIN_INTENT = keccak256("Permit2: approve max USDC to attacker");

    address user;
    uint256 userPk;
    address sessionKey;
    uint256 sessionKeyPk;

    function setUp() public {
        vm.createSelectFork("sepolia", FORK_BLOCK);
        (user, userPk) = makeAddrAndKey("user");
        (sessionKey, sessionKeyPk) = makeAddrAndKey("sessionKey");
        vm.deal(user, 1 ether);

        // 7702 mode: the user's own EOA becomes the smart account — same address, same assets.
        vm.signAndAttachDelegation(SMA_7702, userPk);
    }

    function test_delegationIsLive() public view {
        assertGt(user.code.length, 0, "EOA not delegated to SemiModularAccount7702");
    }

    /// @notice Baseline: the account owner (the EOA itself, the semi-modular fallback signer) can
    ///         sign for the account. Confirms the harness and signature encoding are correct, so the
    ///         denial below is a real denial rather than a malformed signature.
    function test_owner_canSignForAccount() public view {
        bytes32 replaySafe = _smaReplaySafeHash(OFF_CHAIN_INTENT);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPk, replaySafe);
        bytes memory sig = abi.encodePacked(
            OPTS_GLOBAL, FALLBACK_VALIDATION_ID, FINAL_SEGMENT, SIG_TYPE_EOA, r, s, v
        );

        assertEq(IERC1271(user).isValidSignature(OFF_CHAIN_INTENT, sig), ERC1271_MAGIC, "owner cannot sign");
    }

    /// @notice THE RESULT. A session key installed WITHOUT `isSignatureValidation` cannot produce an
    ///         ERC-1271 signature for the account — the account itself reverts, naming the offending
    ///         validation. Asserted on the exact error, not a bare expectRevert.
    function test_sessionKey_withoutSignatureFlag_CANNOT_sign() public {
        uint32 entityId = 1;
        _installSessionKey(entityId, FLAG_IS_USER_OP_VALIDATION); // may execute, may not sign
        assertEq(
            ISingleSignerValidationModule(SINGLE_SIGNER).signers(entityId, user),
            sessionKey,
            "session key not installed"
        );

        bytes memory sig = _sessionKeySig(entityId, OFF_CHAIN_INTENT);

        vm.expectRevert(
            abi.encodeWithSelector(
                SignatureValidationInvalid.selector, bytes24(abi.encodePacked(SINGLE_SIGNER, entityId))
            )
        );
        IERC1271(user).isValidSignature(OFF_CHAIN_INTENT, sig);
    }

    /// @notice Control: the SAME key, the SAME signature construction, installed WITH the flag —
    ///         signs fine. This is what proves the revert above is the flag doing its job rather
    ///         than an encoding mistake.
    function test_sessionKey_withSignatureFlag_CAN_sign() public {
        uint32 entityId = 2;
        _installSessionKey(entityId, FLAG_IS_USER_OP_VALIDATION | FLAG_IS_SIGNATURE_VALIDATION);

        bytes memory sig = _sessionKeySig(entityId, OFF_CHAIN_INTENT);

        assertEq(
            IERC1271(user).isValidSignature(OFF_CHAIN_INTENT, sig),
            ERC1271_MAGIC,
            "flag was granted but signing still failed"
        );
    }

    /// @notice The grant is per-validation, not per-key: the same signer installed twice, once with
    ///         the flag and once without, is accepted under one entity id and refused under the
    ///         other. Signature authority tracks the validation entity, not the key material.
    function test_signingAuthorityIsPerValidation_notPerKey() public {
        _installSessionKey(10, FLAG_IS_USER_OP_VALIDATION); // no signing
        _installSessionKey(11, FLAG_IS_USER_OP_VALIDATION | FLAG_IS_SIGNATURE_VALIDATION); // signing

        // Build both signatures BEFORE arming expectRevert — the helper makes a staticcall to the
        // module, which would otherwise be the call expectRevert latches onto.
        bytes memory grantedSig = _sessionKeySig(11, OFF_CHAIN_INTENT);
        bytes memory refusedSig = _sessionKeySig(10, OFF_CHAIN_INTENT);

        assertEq(
            IERC1271(user).isValidSignature(OFF_CHAIN_INTENT, grantedSig),
            ERC1271_MAGIC,
            "granted entity should sign"
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                SignatureValidationInvalid.selector, bytes24(abi.encodePacked(SINGLE_SIGNER, uint32(10)))
            )
        );
        IERC1271(user).isValidSignature(OFF_CHAIN_INTENT, refusedSig);
    }

    // --- can a scoped key expand its own grant? ----------------------------

    /// @notice A correctly-scoped session key (non-global, no selectors, no signing) cannot call
    ///         `installValidation` on the account. That is the property that makes the grant
    ///         non-self-upgradeable: every widening of scope needs a fresh owner authorization, and
    ///         the holder of the key can never manufacture one.
    function test_scopedSessionKey_cannotInstallAnotherValidation() public {
        uint32 entityId = 20;
        _installSessionKey(entityId, FLAG_IS_USER_OP_VALIDATION);

        // The key tries to grant ITSELF a second, signing-capable validation.
        bytes memory escalation = abi.encodeWithSelector(
            IModularAccount.installValidation.selector,
            bytes25(abi.encodePacked(SINGLE_SIGNER, uint32(21), FLAG_IS_USER_OP_VALIDATION | FLAG_IS_SIGNATURE_VALIDATION)),
            new bytes4[](0),
            abi.encode(uint32(21), sessionKey),
            new bytes[](0)
        );
        bytes memory auth = abi.encodePacked(OPTS_NONE, entityId, FINAL_SEGMENT, SIG_TYPE_EOA, bytes32(0), bytes32(0), uint8(27));

        vm.prank(sessionKey);
        vm.expectRevert();
        IModularAccountRuntime(user).executeWithRuntimeValidation(escalation, auth);

        // ...and no second validation exists.
        assertEq(
            ISingleSignerValidationModule(SINGLE_SIGNER).signers(21, user),
            address(0),
            "session key escalated its own permissions"
        );
    }

    /// @notice The owner, by contrast, CAN widen the scope later — a fresh self-authorized install
    ///         adds signing authority to a key that did not have it. Scope is upgradeable, but only
    ///         by the account owner, never by the delegate.
    function test_owner_canWidenScopeLater() public {
        uint32 entityId = 30;
        _installSessionKey(entityId, FLAG_IS_USER_OP_VALIDATION);

        bytes memory sigBefore = _sessionKeySig(entityId, OFF_CHAIN_INTENT);
        vm.expectRevert(
            abi.encodeWithSelector(
                SignatureValidationInvalid.selector, bytes24(abi.encodePacked(SINGLE_SIGNER, entityId))
            )
        );
        IERC1271(user).isValidSignature(OFF_CHAIN_INTENT, sigBefore);

        // Owner re-installs the SAME entity id with the signing flag added.
        _installSessionKey(entityId, FLAG_IS_USER_OP_VALIDATION | FLAG_IS_SIGNATURE_VALIDATION);

        assertEq(
            IERC1271(user).isValidSignature(OFF_CHAIN_INTENT, _sessionKeySig(entityId, OFF_CHAIN_INTENT)),
            ERC1271_MAGIC,
            "owner could not widen the scope"
        );
    }

    // --- helpers -----------------------------------------------------------

    function _installSessionKey(uint32 entityId, uint8 flags) internal {
        bytes25 config = bytes25(abi.encodePacked(SINGLE_SIGNER, entityId, flags));
        bytes4[] memory selectors = new bytes4[](0);
        bytes memory installData = abi.encode(entityId, sessionKey);
        bytes[] memory hooks = new bytes[](0);

        // In 7702 mode the account address IS the EOA, so a tx from the EOA is a self-call.
        vm.prank(user);
        IModularAccount(user).installValidation(config, selectors, installData, hooks);
    }

    function _sessionKeySig(uint32 entityId, bytes32 digest) internal view returns (bytes memory) {
        bytes32 replaySafe = ISingleSignerValidationModule(SINGLE_SIGNER).replaySafeHash(user, digest);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKeyPk, replaySafe);
        return abi.encodePacked(OPTS_NONE, entityId, FINAL_SEGMENT, SIG_TYPE_EOA, r, s, v);
    }

    /// @dev SemiModularAccountBase wraps the digest in the account's own replay-safe EIP-712 envelope
    ///      for the fallback signer.
    function _smaReplaySafeHash(bytes32 digest) internal view returns (bytes32) {
        bytes32 domainSeparator = keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, block.chainid, user));
        bytes32 structHash = keccak256(abi.encode(REPLAY_SAFE_HASH_TYPEHASH, digest));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}
