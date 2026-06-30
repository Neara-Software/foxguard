// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Negative counterpart for the Solidity taint engine. Each function either
// targets a hard-coded / non-parameter address (so the attacker-controlled
// receiver/recipient position is clean) or only passes the tainted parameter
// into a position the sink does not treat as dangerous. No solidity/taint-*
// rule may fire.
contract Safe {
    address public owner;
    address constant IMPL = 0x1111111111111111111111111111111111111111;

    // delegatecall to a hard-coded constant implementation -> receiver clean.
    // The tainted `data` parameter is only the call payload, not the target.
    function proxy(bytes memory data) public {
        IMPL.delegatecall(data);
    }

    // delegatecall to address(this) -> receiver clean (near-miss: param is data).
    function selfProxy(bytes memory data) public {
        address(this).delegatecall(data);
    }

    // selfdestruct to a fixed owner (state variable, not a parameter) -> clean.
    function kill() public {
        selfdestruct(payable(owner));
    }

    // low-level call to address(this) -> receiver clean.
    function forward(bytes memory data) public {
        address(this).call(data);
    }
}
