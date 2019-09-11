pragma solidity ^0.5.0;

contract SignatureVerifier {
    /// @dev Signature verifier
    function isSigned(address _address, bytes32 messageHash, uint8 v, bytes32 r, bytes32 s) public pure returns (bool) {
        return _isSigned(_address, messageHash, v, r, s) || _isSignedPrefixed(_address, messageHash, v, r, s);
    }

    /// @dev Checks unprefixed signatures.
    function _isSigned(address _address, bytes32 messageHash, uint8 v, bytes32 r, bytes32 s)
        internal pure returns (bool)
    {
        return ecrecover(messageHash, v, r, s) == _address;
    }

    /// @dev Checks prefixed signatures.
    function _isSignedPrefixed(address _address, bytes32 messageHash, uint8 v, bytes32 r, bytes32 s)
        internal pure returns (bool)
    {
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        return _isSigned(_address, keccak256(abi.encodePacked(prefix, messageHash)), v, r, s);
    }
}

contract ButtonChanger is SignatureVerifier {
    enum ButtonColor {RED, BLUE}
    mapping (address => ButtonColor) userColor;
    mapping (address => uint256) userNonce; // for replay protection

    // Normal function
    function changeButtonColor(bool color) public returns (bool changed) {
        if ( color == true ) {
            userColor[msg.sender] = ButtonColor.RED;
        } else {
            userColor [msg.sender] = ButtonColor.BLUE;
        }
        return true;
    }

    // Alternate version of the same function that is meta transactions compatible
    function changeButtonColorDelegated(
        bool color, address user, uint8 v, bytes32 r, bytes32 s
    )
        public returns (bool changed)
    {
        require(
            isSigned(
                user,
                keccak256(
                    abi.encodePacked(
                        byte(0x19), byte(0), address(this),
                        "I authorize my button color to be changed on my behalf.",
                        userNonce[user]
                    )
                ),
                v, r, s
            ),
            "Invalid Signature."
        );
        userNonce[user] += 1;

        // Same logic as before, but using "user" instead of msg.sender
        if ( color == true ) {
            userColor[user] = ButtonColor.RED;
        } else {
            userColor [user] = ButtonColor.BLUE;
        }
        return true;
    }
}