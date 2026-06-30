// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Positive fixture for the Solidity taint engine. Every function flows an
// untrusted function parameter into a taint sink whose attacker-controlled
// position the engine models (delegatecall/callcode receiver, selfdestruct
// recipient, low-level .call receiver).
contract Vulnerable {
    // delegatecall to an attacker-controlled target -> arbitrary-delegatecall
    function proxy(address target, bytes memory data) public {
        target.delegatecall(data);
    }

    // callcode to an attacker-controlled target -> arbitrary-delegatecall
    function legacyProxy(address target, bytes memory data) public {
        target.callcode(data);
    }

    // taint propagates through a local assignment -> arbitrary-delegatecall
    function indirect(address target, bytes memory data) public {
        address t = target;
        t.delegatecall(data);
    }

    // selfdestruct with an attacker-controlled recipient -> unprotected-selfdestruct
    function kill(address payable recipient) public {
        selfdestruct(recipient);
    }

    // low-level call to an attacker-controlled target -> unchecked-call
    function forward(address target, bytes memory data) public {
        target.call(data);
    }
}
