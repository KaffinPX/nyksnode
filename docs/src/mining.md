# Mining

On Nyks, mining is a 2-step process (plus transaction upgrading, but that's not a "requirement" for consensus, so it doesn't count as one of the steps).

## Composing

The composer's role is to select transactions for inclusion, merge them if needed, or create an empty transaction if none are found. Two transactions are always required for a block transaction, so an empty one gets used as a filler when there's nothing else to include. The composer also generates a coinbase transaction for themselves and finishes computing the zk block proof. This requires beefy machinery, like 128+ GB RAM, 96 cores.

A composer always has to merge two transactions for generating a block transaction, to discourage skipping transactions just to get faster proof generation.

Distribution of the block reward is determined by the composer.

## Mining

Typical PoW mining: a memory-heavy variant of Tip5 is used, and you search for a nonce that satisfies the block's target.

Tip5's research paper can be found here: https://eprint.iacr.org/2023/107.pdf.
Tip5 is also a crucial part of computing ZK proofs [zk.md](zk.md)), so giving miners an incentive to make it faster will probably be worth it in the long term.

Miners choose whichever block template from a composer favors them most.

## Upgraders

There's one extra role for upgrading transactions, called upgraders.

In parallel to composers, upgraders can raise transaction proofs to a quality suitable for on-chain inclusion, merge them for easier inclusion (turning them into a single transaction so the composer doesn't waste time merging), and collect fees from transactions through a process called "gobbling."

Also requires beefy machinery for competition.