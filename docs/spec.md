# Zuika Spec

## Sui Background

### Checkpoint

A checkpoint is essentially a “block” in other blockchain’s terminology. Checkpointing is currently performed once
around 2 seconds and each checkpoint is signed by at least a supermajority of 2f+1 nodes. To verify a Sui checkpoint in
a light client, we essentially just need to check the threshold signature attached to the checkpoint. But the committee
who signs the checkpoints is a dynamic set of authorities, and we need to know which public keys to use for the
signature verification. That means the light client needs to be aware of the committee reconfiguration.

### Committee Reconfiguration

Time on Sui is organized into epochs. Every epoch lasts around 43,200 checkpoints. This number varies depending on how
fast checkpoints are finalized. The goal is to make each epoch last around 24 hours. At the end of each epoch, a special
last checkpoint includes the next committee’s public keys. Checkpoints are signed by the current committee. Therefore,
from a light client’s perspective, we only store an initial set of trusted committee public keys once, and update the
light client’s knowledge of the committee once a day. Everything after the initial hardcoded committee is totally
dependent on the security guarantees of Sui itself.

### Signature Schemes

The signature scheme used for signing checkpoints is directly related to the size of our ZK circuits. Sui uses BLS12-381
for signing checkpoints. This is especially efficient for in-circuit signature verification because BLS signatures are
aggregatable so that we only need to do around 113 * 2/3 public key additions and then do the pairing once to verify all
signatures.

## Design

### Overview

- Fetch a recent committee, use that as the weak subjectivity committee
- 