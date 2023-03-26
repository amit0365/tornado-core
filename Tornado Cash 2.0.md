# Tornado Cash Core 
###### tags: `Tornado Cash`

1) When users deposit funds in Tornado Cash, the contract creates a note that includes a commitment and a nullifier hash. 
2) First it generates two random numbers - secret and nullifier. These are hashed together to form a commitment. 
3) The nullifier hash and the commitment is sent along with the deposit. 
4) Then the smart contract takes the commitment hash and adds it to the merkle tree that is stored and built on-chain. 
5) The nullifier hash is then broadcast to the Tornado Cash network, where it is added to a list of spent nullifiers. This prevents anyone else from withdrawing funds using the same note.

The merkle root contains the users node. The contract doesn't need to have the latest version of the tree as the user will be present as a node once inserted.


```circom=
// computes Pedersen(nullifier + secret)
template CommitmentHasher() {
    signal input nullifier;
    signal input secret;
    signal output commitment;
    signal output nullifierHash;

    component commitmentHasher = Pedersen(496);
    component nullifierHasher = Pedersen(248);
    component nullifierBits = Num2Bits(248);
    component secretBits = Num2Bits(248);
    nullifierBits.in <== nullifier;
    secretBits.in <== secret;
    for (var i = 0; i < 248; i++) {
        nullifierHasher.in[i] <== nullifierBits.out[i];
        commitmentHasher.in[i] <== nullifierBits.out[i];
        commitmentHasher.in[i + 248] <== secretBits.out[i];
    }

    commitment <== commitmentHasher.out[0];
    nullifierHash <== nullifierHasher.out[0];
}
```
When a user wants to withdraw funds from the contract, they must first prove ownership of a note. To do this, they reveal the commitment and the nullifier hash.

The snark prover submitted by the user contains root, a public input root and private inputs: secret, nullifier,  pathElements and pathIndices.

The Proof computes two hashes. A commitment hash of the secret and the nullifier. Second a hash of just the nullifier, called nullifier hash. For an external observer, these two hashes seem uncorrelated

The contract checks that the root is one of the last 100? merkle roots and whether the nullifier hash is unique.

It verifies the nullifier hash against a list of previously spent nullifiers. If the nullifier hash is found in the list, the transaction is rejected as a double spend attempt.

If the nullifier hash is not found in the list, the transaction is added to the blockchain the contract releases the funds to the withdrawer. This mechanism of using nullifier to prevent double spend was first adopted by Zcash.


```circom=
// Verifies that commitment that corresponds to given secret and nullifier is included in the merkle tree of deposits
template Withdraw(levels) {
    signal input root;
    signal input nullifierHash;
    signal input recipient; // not taking part in any computations
    signal input relayer;  // not taking part in any computations
    signal input fee;      // not taking part in any computations
    signal input refund;   // not taking part in any computations
    signal private input nullifier;
    signal private input secret;
    signal private input pathElements[levels];
    signal private input pathIndices[levels];

    component hasher = CommitmentHasher();
    hasher.nullifier <== nullifier;
    hasher.secret <== secret;
    hasher.nullifierHash === nullifierHash;

    component tree = MerkleTreeChecker(levels);
    tree.leaf <== hasher.commitment;
    tree.root <== root;
    for (var i = 0; i < levels; i++) {
        tree.pathElements[i] <== pathElements[i];
        tree.pathIndices[i] <== pathIndices[i];
    }

    // Add hidden signals to make sure that tampering with recipient or fee will invalidate the snark proof
    // Most likely it is not required, but it's better to stay on the safe side and it only takes 2 constraints
    // Squares are used to prevent optimizer from removing those constraints
    signal recipientSquare;
    signal feeSquare;
    signal relayerSquare;
    signal refundSquare;
    recipientSquare <== recipient * recipient;
    feeSquare <== fee * fee;
    relayerSquare <== relayer * relayer;
    refundSquare <== refund * refund;
}
```