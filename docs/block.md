# Block

On Nyks, a block consists of a kernel and a proof. The kernel is made up of a header, body, and appendix.

## Header

The header includes:

* Version
* Height
* Previous block digest, linking it to its parent
* Timestamp
* Proof-of-work data, consisting of a root, two authentication paths (`path_a`, `path_b`), and a nonce
* Cumulative proof-of-work, the running total of work done across the chain
* Difficulty
* Guesser receiver data, describing where the guesser's portion of the block reward goes

## Body

The body includes:

* The transaction kernel, aka the block's inputs and outputs. At this level there's no notion of individual transactions, just the merged set of inputs and outputs that make up the block (its scheme is similar to a single transaction kernel, as explained in [transactions.md](transactions.md))
* The mutator set accumulator, reflecting the mutator set state after this block without guesser UTXOs
* The lock-free MMR accumulator (will be removed)
* The block MMR accumulator, a Merkle mountain range over all block digests in the chain up to and including this block. It lets anyone produce a compact membership proof that a given block is part of the chain's history, without needing the full chain

## Appendix

Contains a block's claims, which are recursively proven on the block's proof.