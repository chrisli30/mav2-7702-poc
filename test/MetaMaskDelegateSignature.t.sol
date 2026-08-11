// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}

interface IStatelessDeleGator {
    function NAME() external view returns (string memory);
    function delegationManager() external view returns (address);
}

/// @notice The same question, asked of MetaMask's EIP-7702 delegator: can a party holding delegated
///         authority produce an ERC-1271 signature *as the account*?
///
///         Asked because MetaMask's scoping model is otherwise the closest analogue to Calibur's —
///         authority is bounded by attached policy contracts (caveat enforcers there, hooks there),
///         and by their own documentation a delegation with no caveats has "infinite and unbounded
///         authority to make any execution the original account can make." If the signature path
///         were equally permissive, a caveat-scoped delegate would be able to mint Permit2/Seaport
///         signatures the caveats never see — caveat enforcers run at redemption, not at signature
///         validation.
///
///         **Answer: no, and not by policy — by construction.** `EIP7702StatelessDeleGator` is
///         stateless by design: it stores no signer data, so `_isValidSignature` recovers the
///         signature and compares it to `address(this)` — the EOA itself — and nothing else. The
///         signature path never reads delegation state at all. There is no configuration in which a
///         delegate signs for the account.
///
///         So MetaMask splits the two authorities the opposite way from Calibur: execution scoping
///         is fail-open (caveats are "strongly recommended", not required), while signing authority
///         is not merely fail-closed but unreachable.
contract MetaMaskDelegateSignatureTest is Test {
    /// @dev MetaMask's canonical EIP-7702 delegation target.
    address constant MM_DELEGATOR = 0x63c0c19a282a1B52b07dD5a65b58948A07DAE32B;

    /// @dev Same pinned block as the MA v2 suite, so both comparisons read the same chain state.
    uint256 constant FORK_BLOCK = 11_440_000;

    bytes4 constant ERC1271_MAGIC = 0x1626ba7e;
    bytes4 constant SIG_VALIDATION_FAILED = 0xffffffff;

    bytes32 constant DIGEST = keccak256("Permit2: approve max USDC to attacker");

    address user;
    uint256 userPk;
    address delegate;
    uint256 delegatePk;

    function setUp() public {
        vm.createSelectFork("sepolia", FORK_BLOCK);
        (user, userPk) = makeAddrAndKey("user");
        (delegate, delegatePk) = makeAddrAndKey("delegate");
        vm.deal(user, 1 ether);

        vm.signAndAttachDelegation(MM_DELEGATOR, userPk);
    }

    function test_delegationIsLive() public view {
        assertGt(user.code.length, 0, "EOA not delegated to the MetaMask delegator");
        assertEq(IStatelessDeleGator(MM_DELEGATOR).NAME(), "EIP7702StatelessDeleGator", "unexpected implementation");
    }

    /// @notice Baseline — the EOA itself signs for its own account. Confirms the harness is right,
    ///         so the refusal below is a real refusal.
    function test_owner_canSignForAccount() public view {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPk, DIGEST);
        assertEq(
            IERC1271(user).isValidSignature(DIGEST, abi.encodePacked(r, s, v)),
            ERC1271_MAGIC,
            "owner could not sign for its own account"
        );
    }

    /// @notice THE RESULT. Any signer that is not the EOA is refused — returns
    ///         SIG_VALIDATION_FAILED rather than the magic value.
    ///
    ///         Note there is deliberately no delegation set up in this test, and that is the point:
    ///         delegations are off-chain signed objects that live with the delegate, and the
    ///         account's signature path never consults them. Holding one — with or without caveats —
    ///         cannot change this outcome, because no code path reads it.
    function test_delegate_CANNOT_signForAccount() public view {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(delegatePk, DIGEST);
        assertEq(
            IERC1271(user).isValidSignature(DIGEST, abi.encodePacked(r, s, v)),
            SIG_VALIDATION_FAILED,
            "a non-owner signature was accepted for the account"
        );
    }

    /// @notice Generalises the above: no key other than the EOA's is ever accepted.
    function testFuzz_onlyTheEOAKeyIsAccepted(uint256 otherPk) public view {
        otherPk = bound(otherPk, 1, type(uint128).max);
        vm.assume(vm.addr(otherPk) != user);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(otherPk, DIGEST);
        assertEq(
            IERC1271(user).isValidSignature(DIGEST, abi.encodePacked(r, s, v)),
            SIG_VALIDATION_FAILED,
            "some non-owner key produced a valid account signature"
        );
    }

    /// @notice The DelegationManager is the account's execution-side counterparty and is a distinct
    ///         contract from the signature path — recorded so the separation of the two authorities
    ///         is visible rather than asserted.
    function test_delegationManagerIsSeparateFromSignaturePath() public view {
        address manager = IStatelessDeleGator(MM_DELEGATOR).delegationManager();
        assertTrue(manager != address(0), "no delegation manager configured");
        assertTrue(manager != user, "delegation manager is not the account");
        assertTrue(manager != MM_DELEGATOR, "delegation manager is not the implementation");
    }
}
