# ZK

Nyks uses Triton VM as the underlying VM for its STARK proofs. It is a stack-based virtual machine with efficient recursive verification, making it suitable for an indefinitely growing blockchain.

Because each block can verify the proof from the previous block, the latest block can represent the validity of the entire chain and its current state. This keeps verification succinct without requiring the whole blockchain to be verified from scratch.

Succinctness is not implemented yet.

Triton VM's repository can be found here: https://github.com/TritonVM/triton-vm.