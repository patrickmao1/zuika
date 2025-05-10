# Zuika: A Sui ZK Light Client

Patrick Mao <patrickmao@live.com>

## Abstract

Zuika is a ZK light client that is able to verify Sui checkpoints, transactions, and effects on Ethereum. At the highest
level of abstraction, it can be considered an oracle that can be queried by smart contracts on Ethereum for events
happen on Sui. Applications can use Zuika to implement a unidirectional information bridge from Sui to Ethereum. Zuika
achieves this information bridging without trusting any third parties, and its security depends solely on the underlying
zero-knowledge proof's security promises and implementation correctness.

## 1. Introduction

In the past decade, distributed ledger systems or blockchain systems have established themselves into a substantial
industry. Bitcoin led the initial inception of blockchains and Ethereum led the way of generalizing blockchains into not
only distributed ledgers but a secure and shared world computer. There are also newer systems like the Sui blockchain
that are built on top of the experience of the pinoeers. Old or new, many blockchain systems have several common
limitations. First, on-chain resources are expensive. Computation and data storage remain a significant cost to the
users of the blockchain. Second, the type of data an on-chain program (smart contract) can access is limited. For
example, a contract cannot access data from other chains (an interoperability problem), and it cannot even access some
data on the same chain such as data that exist in the concensus layer, or historical data (a data availability problem).
One could build an on-chain system that "checkpoints" historical data as the chain state progresses. But doing so
frequently the developers often expose themselves to the first problem where transaction and on-chain storage cost deter
them away from scaling their project.

To solve the data access problem, many projects settle for less-than-ideal models. For blockchain interoperability, the
most common model is the notary model [1]; and for same-chain data access, earlier projects could only rely on either
some expensive on-chain checkpointing mechanisms, or trusting an off-chain oracle completely [2]. These models pose
centralization concerns, and indeed the many bridge and centralized exchange hacks [3] happened in the past few years
have proven the point.

The alternative to trusting a third party for on-chain data has always existed. Many blockchains support light
clients -- blockchain client so light weight that it can verify blockchain states without needing to download the entire
chain [4]. But moving a light client on-chain has always been impractical. For example, in order to grant an on-chain
program the ability to verify some historical transaction effects, the program must have the ability to verify the
blocks in which those effects exist. In Proof-of-Stake blockchains such as Sui, this implies the knowledge Sui's
authority committee and their public keys, which can be prohibitively expensive. The verification of various types
signatures (e.g. ECDSA, BLS) also aren't standardized or well supported across different chains. These limitations made
on-chain light clients largely impractical before the emergence of Zero-knoeldge proof technologies.

The recent advancement in Zero-knowledge Proof (ZKP) technologies [5] completely changed the landscape. Applications
such as on-chain light clients that previously deemed "too expensive" are now within reach as data verifications can be
delegated to the proving work off-chain in arithmetic circuits [6]. Many developers rush to implement ZK based
blockchain applications. Among them, using ZK techonologies to achieve blockchain bridges is popular.

**From the Academia: zkBridge.** zkBridge [7] lays a rigorous foundation in the implementation of the ZKP-based
blockchain bridge from Tendermint-based blockchains to Ethereum. It focuses on the overall architecture of their system
and rigorous proving of the completeness and soundness of their ZK circuits. The most impactful method developed in the
paper regarding using ZK to verify block header signatures is the use of aggregated proofs which enables distributed
proving on data-parallel circuits. Because the heaviest workload of proving a block’s validity in a ZK light client is
the verification of signatures which means the signature check sub-circuits are just copies of each other, the authors
developed an idea to parallelize N instances of the signature proofs in a distributed manner and then aggregate the
verification of these proofs in a master circuit. This gives us a succinct final proof that is independent from N. Since
the proof generated is not directly verifiable on Ethereum, zkBridge wraps the proof in another Groth16 proof over the
BN254 curve for which there exists efficient precompiles for pairing check on Ethereum.

**From the Industry: Brevis zkCoprocessor.** There aren't much academic literature in the area of applied ZK bridges,
but more implementations of ZK bridges exist in the industry. Among them, Brevis’ zkCoprocessor [8] seems to be the only
project that is still being maintained. Brevis’ architecture allows users (developers) to compile and run their circuits
through their SDK [9]. The circuit is then embedded in the context of a larger backend proof system which provides the
user circuit verified Ethereum block headers, transactions and receipts. The contract repo suggests that the final
verification is a Groth16 proof which means that the backend proof system is either different from the user ones, or is
wrapped in a final Groth16 proof for more efficient on-chain verification. Every time the sync committee is updated,
there is a proof that commits all the committee public keys into a single root and stored on-chain in the light client
contract. The stored root is a public input in the block signature verification proof so that when the proof is verified
by the light client contract, it can prove the block is signed by a committee that is known by the light client
contract. This differs from how a normal (off-chain) Ethereum light client as the normal ones saves the entirety of the
public keys on disk.

**From the Industry: Axiom Coprocessor.** The functionalities of Axiom Coprocessor [10] are almost identical to Brevis’
zkCoprocessor. The major difference is that Axiom uses PLONK for all their proof systems as opposed to Brevis’ GROTH16.
Another difference is that for the storage of the proven blocks, Axiom uses Padded Merkle Mountain Range (PMMR) as
opposed to the Sparse Merkle Tree (SMT) that Brevis uses. This difference likely comes from favoring different
trade-offs. PMMR is infinitely updatable but has the cost of maintaining multiple roots while SMT is much simpler and
only has one single root to manage which saves storage cost on-chain but has a finite capacity.

### The Focus of This Paper

To our knowledge, no existing work has investigated into the possibility of building an efficient ZK light client for
Sui. This paper focuses on uncovering and addressing the challenges imposed by such task. We show that building an
economically viable Sui ZK light client is possible and we evaluate the cost of verification on Ethereum, which is
typically the most expensive blockchain to run smart contracts on.

## 2. Background

### 2.1 The Sui Blockchain

TODO

### 2.2 Blockchains and Light Clients

Blockchains are distributed systems that maintain a shared ledger of transactions in a decentralized temper-proof
manner. A typical decentralized blockchain consists of a network of member nodes ranging from tens to hundreds of
thousands. The participants of the network reach consensus on the order of blocks containing user transactions and
execute them to alter blockchain state.

#### 2.2.1 Proof-of-Stake Blockchains

Today's top blockchain systems mostly employ the Proof-of-Stake (PoS) consensus model. The users sign transactions via
cryptographic signature schemes and submit transactions to the blockchain. The blockchain members, often called
*validators* or *authorities* (used interchangeably), checks the validity of the transactions by verifying its
signature. A batch of transactions is typically packaged into a *block* and validators in the blockchain network checks
the validity of the blocks and provide attestations by **signing the blocks**. This action is often referred to as "
voting". In typical PoS, how much *voting power* that a validator's signature represents is directly determined by how
much *stake* (in terms of cryptocurrencies) they have locked into the system. Different blockchain have different
requirements in how much voting power is needed on single block for it to be considered *finalized*. For example,
Ethereum requires more than $\frac{2}{3}$ voting power of the entire network [citation]; while in Algorand, since the
voting committee is dynamic and can be different for each block, the absolute amount of voting power required is also
dynamic. Nontheless, Algorand still requires all blocks to gather more than $\frac{2}{3}$ voting power of the specific
committee for it to be considered finalized. The network reach consensus on the order of the blocks, execute the
transactions in the blocks to change their state. Since blockchains are modeled as deterministic state machines, a total
order of transactions implies the eventual consistency of individual nodes' state.

#### 2.2.2 Blockchain Light Clients

TODO

## 3. Implementation

### 3.1 Challenges
