# Blockchain DLT Attacks and Weaknesses Enumeration / List of Blockchain attacks




| Name of weakness | Alternate names | Type | Description | Contributes to | Affected Technology/Components | CWE(s) | Related CWE(s) | Source Material | Extended Description | Modes of Introduction | Phase | Applicable Platforms | Common Consequences | Demonstrative Examples | Observed Examples | Memberships | Taxonomy Events | Related Attack Patterns | References | Google Doc | Github Doc |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
Account Hijacking |  | Weakness |  |  | Node User, Exchange |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
API Exposure | RPC API Exposure | Weakness | If an API is improperly exposed an attacker can attack it |  | Blockchain Network Level |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Artificial Difficulty Increases |  | Weakness |  |  | Blockchain Network Level |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Balance Attack |  | Weakness |  |  |  |  |  | https://ieeexplore.ieee.org/document/8023156 |  |  |  |  |  |  |  |  |  |  |  |  | 
Block Forger DoS |  | Weakness |  |  | Blockchain Network Level |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Block Mining Finney Attack |  | Weakness |  | Consensus Attack | Blockchain Network Level |  |  |  |  |  |  |  |  |  |  |  |  |  | https://bitcoin.stackexchange.com/questions/4942/what-is-a-finney-attack |  | 
Block Mining Race Attack |  | Weakness | A variation on the Finney attack | Consensus Attack | Blockchain Network Level |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Block Mining Timejack Attack |  | Weakness | By isolating a node the time signal can be manipulated getting the victim out of synchronization | Consensus Attack | Blockchain Network Level |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Block Reordering Attack |  | Weakness | Certain cryptographic operations (such as using CBC or ECB incorrectly) allow blocks to be re-ordered and the results will still decrypt properly |  | Cryptography |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Blockchain Ingestion |  | Weakness |  |  | Multiple |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Blockchain Network Lacks Hash Capacity |  | Weakness | The Blockchain/DLT network lacks hashing capacity, an attacker can rent sufficient hashing power to execute a 51% Attack | Consensus Majority Attack | Blockchain Network Level |  |  | DLTI-2020-01-26-1, DLTI-2020-02-11-1, DLTI-2018-10-24-1 |  |  |  |  |  |  |  |  |  |  |  |  | 
Blockchain Network Partitioning Attack | Partition Routing Attack  | Weakness |  | Consensus Majority Attack | Blockchain Network Level |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Blockchain Peer flooding Attack | Unlimited node creation | Weakness | By creating a large number of fake peers in a network (peer to peer or otherwise) an attacker can cause real nodes to slow down or become non responsive as they attempt to connect to the newly announced peers. |  | Blockchain Network Level |  |  | https://lisk.io/blog/development/lisk-core-2.0.1-released-fix-p2p-network-vulnerability |  |  |  |  |  |  |  |  |  |  |  |  | 
Blockchain Peer flooding Attack Slowloris variant |  | Weakness | By creating a large number of slow peers  (real systems that respond very slowly to network requests) in a network an attacker can cause real nodes to slow down or become non responsive as they attempt to connect to the newly announced peers. Unlike fake peers that do not exist these slowloris peers are real but communicate slowly enough to hold sockets and resources open for minutes or hours. |  | Blockchain Network Level |  |  | https://lisk.io/blog/development/lisk-core-2.0.1-released-fix-p2p-network-vulnerability |  |  |  |  |  |  |  |  |  |  |  |  | 
Blockchain reorganization attack | Alternative history attack, history rewrite attack | Weakness | Also referred to as an alternative history attack |  | Blockchain Network Level |  |  |  |  |  |  |  |  |  |  |  |  | Double Spending |  |  | 
Consensus 34% Attack |  | Weakness | 34% Attack against BFT network, a specific instance of Consensus Majority Attack | Consensus Majority Attack | Blockchain Network Level |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | https://github.com/cloudsecurityalliance/Glossary/blob/master/glossary/3/34%25%20attack%20(aka%20Consensus%20HiJacking).md
Consensus 51% Attack |  | Weakness | 51% Attack against DLT network, a specific instance of Consensus Majority Attack | Consensus Majority Attack | Blockchain Network Level |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | https://github.com/cloudsecurityalliance/Glossary/blob/master/glossary/5/51%25%20attack%20(aka%20Consensus%20HiJacking).md
Consensus Attack |  | Weakness | Attacks against the consensus protocol and system in use can take many forms and are not limited to gaining control of the consensus mechanism but can also be used to slow down consensus for example |  | Blockchain Network Level |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Consensus Delay Attack |  | Weakness | Consensus Delay Attacks can allow malicious miners to gain time in order to execute other attacks | Consensus Attack | Blockchain Network Level |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Consensus Majority Attack |  | Weakness | Attackers can try to gain a consensus majority in order to control the contents of the Blockchain | Consensus Attack | Blockchain Network Level |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Credential Stuffing  |  | Weakness | Attackers use spilled or otherwise leaked credentials and account names to try name/password combinations with a higher likelihood of success against services requiring authentication |  | Exchange |  |  | https://owasp.org/www-community/attacks/Credential_stuffing |  |  |  |  |  |  |  |  |  |  |  |  | 
Cryptomining | Cryptojacking | Weakness | Cryptomining (also known as Cryptojacking) involves an attacker using a victims compute resources to mine crypto currencies, this can range from using malware to stolen credentials to gain access to systems |  | multiple |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Cryptomining Malware | Cryptojacking Malware | Weakness |  |  | Multiple |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Data corruption |  | Weakness |  |  | Oracles |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Dictionary Attack |  | Weakness | Attackers use dictionaries of known passwords, a subset of brute force attacks, this can be used against services requiring login, or against cryptographically protected data requiring a password or passphrase to access it such as a wallet |  | Exchange, Wallet |  |  |  |  |  |  |  |  |  |  |  |  | Credential stuffing |  |  | 
Distributed-Denial-of-Service Attack | DDoS Attack | Weakness |  |  | Blockchain Network Level |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
DNS Attacks |  | Weakness |  |  | Multiple |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
DoS against Ethereum 2.0 validator to trigger penalty for being offline |  | Weakness |  |  | Blockchain Network Level |  |  | https://codefi.consensys.net/blog/rewards-and-penalties-on-ethereum-20-phase-0 |  |  |  |  |  |  |  |  |  |  |  |  | 
Double Spending Attack |  | Weakness |  |  | Blockchain Network Level |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Download of Data Without Integrity Check |  | Weakness |  |  | Multiple |  |  |  |  |  |  |  |  |  |  |  |  | CWE-494 / SIngle perspective |  |  | 
Dusting attack |  | Weakness |  |  | Wallet |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Eclipse Attack |  | Weakness |  | Consensus Majority Attack | Blockchain Network Level |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | https://github.com/cloudsecurityalliance/Glossary/blob/master/glossary/E/Eclipse%20Attack.md
EOS RAM Vulnerability |  | Weakness |  |  | Blockchain Network Level |  |  | https://www.reddit.com/r/eos/comments/9akg1y/eosio_ram_exploit_please_read/ |  |  |  |  |  |  |  |  |  |  |  |  | 
Ethereum Solidity prior to 0.5.0 view promise not enforced |  | Weakness | Ethereum Solidity prior to 0.5.0 did not enforce the view promise |  |  |  |  | https://circle.cloudsecurityalliance.org/community-home1/digestviewer/viewthread?GroupId=133&MessageKey=2fce11ab-c223-4718-8310-3058e0a2fbb6&CommunityKey=a9786cbe-105a-420f-a353-8bbe10ab684d&tab=digestviewer&ReturnUrl=%2fcommunity-home1%2fdigestviewer%3ftab%3ddigestviewer%26CommunityKey%3da9786cbe-105a-420f-a353-8bbe10ab684d&SuccessMsg=Thank%20you%20for%20submitting%20your%20message. |  |  |  |  |  |  |  |  |  |  |  |  | 
Evil Maid attack |  | Weakness | The evil maid attack is generally accepted as a situation where someone has temporary access to your hardware (e.g. a hotel maid) for several minutes or hours, and does not want to leave evidence of tampering if possible. |  | Exchange, Wallet |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Failure to Update |  | Weakness | Failure to update software with known security vulnerabilities can result in known vulnerabilities being present and exploited |  | Node User |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Fixed Consensus Termination |  | Weakness |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Flawed Blockchain Network Design |  | Weakness |  |  | Blockchain Network Level |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Fork-after-withhold Attack | FAW Attack | Weakness |  | Malicious Mining | Consensus Protocols |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Freeloading |  | Weakness |  |  | Oracles |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Front Running |  | Weakness |  |  | Multiple |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Front Running displacement |  | Weakness |  |  | Multiple |  |  | DLTSEC-0004 |  |  |  |  |  |  |  |  |  |  |  |  | 
Front Running insertion |  | Weakness |  |  | Multiple |  |  | DLTSEC-0004 |  |  |  |  |  |  |  |  |  |  |  |  | 
Front Running Mempool |  | Weakness | Front running by looking at the contents of the mempool or other public sources of transactions that are being processed but have not yet been finalized. Attackers can potentially "beat" items in the mempool by offering higher payments for their own transactions |  | Multiple |  |  | https://consensys.github.io/smart-contract-best-practices/known_attacks/ https://medium.com/@danrobinson/ethereum-is-a-dark-forest-ecc5f0505dff |  |  |  |  |  |  |  |  |  |  |  |  | 
Front Running Oracle |  | Weakness | Front running by monitoring oracles especially where the oracle data has to be entered on chain to be acted on can create arbitrage oppurtunities |  |  |  |  | https://medium.com/@galvanek.m/synthetix-the-battlefield-a15a7104587c |  |  |  |  |  |  |  |  |  |  |  |  | 
Front Running suppression |  | Weakness |  |  | Multiple |  |  | DLTSEC-0004 |  |  |  |  |  |  |  |  |  |  |  |  | 
Frozen ether |  | Weakness |  |  | Smart Contract |  |  | https://arxiv.org/pdf/1908.04507.pdf |  |  |  |  |  |  |  |  |  |  |  |  | 
Gas Limit DoS on the Blockchain Network via Block Stuffing | Block Stuffing | Weakness |  |  | Blockchain Network Level |  |  | https://consensys.github.io/smart-contract-best-practices/known_attacks/ |  |  |  |  |  |  |  |  |  |  |  |  | 
Hard fork software update |  | Weakness |  |  | Blockchain Network Level |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Hash functions |  | Weakness | Using weak hash functions (e.g. MD5) or using them incorrectly (e.g. failure to include a nonce to prevent replay attacks) can result in vulnerabilities |  | Cryptography |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Homomorphic encryption |  | Weakness |  |  | Cryptography |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Identity and Access Management Overview |  | Weakness |  |  | Node User |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Immutable Bugs |  | Weakness | DLT/Blockchains can include immutable data, protocols, smart contract implementations and so on, thus it is possible that a vulnerability can be found in a component that cannot be updated at all, or reasonably (e.g. it would require a governance decision or change to update) |  | Multiple |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Implementation of something they should use a standard library for |  | Weakness | Should we codify some version of "Not invented here" syndrome as a vulnerability class? |  | Multiple |  |  | DLTI-2019-02-26-01 |  |  |  |  |  |  |  |  |  |  |  |  | 
Indistinguishable chains  |  | Weakness | If a transaction lacks information it is possible that the wrong chain may be used when sending the transaction in. |  | Data Layer |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Insecure API Connections |  | Weakness |  |  | Node User |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Insider Threat |  | Weakness |  |  | Multiple |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Leading ether to arbitrary address |  | Weakness |  |  | Multiple |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Long-Range Attack |  | Weakness |  |  | Consensus Protocols |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Majority attack |  | Weakness |  |  | Oracles |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Malfunctioned MSP |  | Weakness |  |  | Node User |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Malicious Mining |  | Weakness |  |  | Consensus Protocols |  | Consensus Attack |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Malicious Web Extensions |  | Weakness | A number of malicious web browser extensions have been found that steal crypto currency credentials or conduct crypto mining on the users web browser |  | Multiple |  |  | DLTI-2020-04-14-4 |  |  |  |  |  |  |  |  |  |  |  |  | 
Membership Service Provider Attacks |  | Weakness |  |  | Node User |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Mirroring |  | Weakness |  |  | Oracles |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Multi-Factor Authentication (MFA) | MFA | Defense |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Multiple signatures |  | Weakness |  |  | Cryptography |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Network Routing Attacks |  | Weakness | Network routing attacks allow attackers to partition the blockchain network (for example via DNS or BGP based attacks) or otherwise manipulate nodes in order to aid in other attacks | Consensus Majority Attack | Multiple |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | https://github.com/cloudsecurityalliance/Glossary/blob/master/glossary/N/Network%20Routing%20Attacks.md
Non-existent accounts |  | Weakness | In some blockchains it is possible to create accounts/wallets that are not present on the blockchain which can result in problems |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Nothing at Stake |  | Weakness |  |  | Consensus Protocols |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
On-chain data confidentiality |  | Weakness |  |  | Oracles |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Orphan Blocks |  | Weakness |  |  | Multiple |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Parity Multisig Wallet Attack |  | Weakness | Access to "initWallet" method was not properly restricted in the Parity multisig wallet software |  | Wallet |  |  | DLTI-2017-11-06-1 |  |  |  |  |  |  |  |  |  |  |  |  | 
Permissioned Blockchain MSP DoS |  | Weakness |  |  | Blockchain Network Level |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Phishing Attack |  | Weakness |  |  | Exchange, Wallet |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Pool Hopping |  | Weakness |  |  |  |  |  | https://bitcoin.stackexchange.com/questions/5072/what-is-pool-hopping |  |  |  |  |  |  |  |  |  |  |  |  | 
Private Key Leakage Attack |  | Weakness |  |  | Node User |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Public peer selection |  | Weakness |  |  | Blockchain Network Level |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Replay Attack |  | Weakness |  |  | Blockchain Network Level |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Ring signatures |  | Weakness |  |  | Cryptography |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
RPC Call vulnerability |  | Weakness |  |  | Node User |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Selfish Mining Attack (Block Withholding Attack) |  | Weakness |  | Malicious Mining | Consensus Protocols |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
SIM Swap |  | Weakness | Through a number of means (stolen credentials, social engineering, phishing, etc.) an attacker can hijack a phone number (the "SIM") and redirect calls/texts to a device under their control, if SMS or phone based 2FA/MFA is used this would allow the attacker to use it. |  | Multiple |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Single Perspective Validation |  | Weakness | Single Perspective Validation |  | Multiple |  |  |  |  |  |  |  |  |  |  |  |  |  |  | https://docs.google.com/document/d/1ntVHuprosF15UdDU7EOjm6Kfq2NXB-IATuhFP0a7NZY/edit | 
Smart Contract  Use of Outdated Compiler Version |  | Weakness |  |  | Smart Contract |  | CWE-937: Using Components with Known Vulnerabilities | https://swcregistry.io/docs/SWC-102 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Access Control - Smart Contract Initialization |  | Weakness |  |  | Smart Contract |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Arbitrary Jump with Function Type Variable |  | Weakness |  |  | Smart Contract |  | CWE-695: Use of Low-Level Functionality | https://swcregistry.io/docs/SWC-127 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Assert Violation |  | Weakness |  |  | Smart Contract |  | CWE-670: Always-Incorrect Control Flow Implementation | https://swcregistry.io/docs/SWC-110 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Authorization through tx.origin | Smart Contract Authorization through tx.origin | Weakness |  |  | Smart Contract |  | CWE-477: Use of Obsolete Function | https://swcregistry.io/docs/SWC-115 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Block values as a proxy for time |  | Weakness |  |  | Smart Contract |  | CWE-829: Inclusion of Functionality from Untrusted Control Sphere | https://swcregistry.io/docs/SWC-116 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Call Depth Attack |  | Weakness |  |  | Smart Contract |  |  | https://consensys.github.io/smart-contract-best-practices/known_attacks/ |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Call to Unknown function via fallback() |  | Weakness |  |  | Smart Contract |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Code With No Effects |  | Weakness |  |  | Smart Contract |  | CWE-1164: Irrelevant Code | https://swcregistry.io/docs/SWC-135 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Cross-Function Race Condition |  | Weakness |  | Smart Contract Race Conditions | Smart Contract |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract default fallback address attack |  | Weakness |  |  | Smart Contract |  |  | DLTI-2020-04-08-1 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Delegate call injection |  | Weakness |  |  | Smart Contract |  |  | https://arxiv.org/pdf/1908.04507.pdf |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Delegate call to Untrusted Callee |  | Weakness |  |  | Smart Contract |  | CWE-829: Inclusion of Functionality from Untrusted Control Sphere | https://swcregistry.io/docs/SWC-112 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract DoS |  | Weakness |  |  | Smart Contract |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract DoS With Block Gas Limit |  | Weakness |  |  | Smart Contract |  | CWE-400: Uncontrolled Resource Consumption | https://swcregistry.io/docs/SWC-128 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract DoS with Failed Call |  | Weakness | Related to mishandled exceptions |  | Smart Contract |  | CWE-703: Improper Check or Handling of Exceptional Conditions | https://swcregistry.io/docs/SWC-113 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract DoS with unbounded operations |  | Weakness |  |  | Smart Contract |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract DoS with unexpected revert |  | Weakness |  |  | Smart Contract |  |  | https://ethereum-contract-security-techniques-and-tips.readthedocs.io/en/latest/known_attacks/ |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Erroneous constructor name |  | Weakness |  |  | Smart Contract |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Erroneous visibility |  | Weakness |  |  | Smart Contract |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Ether Lost in Transfer |  | Weakness |  |  | Smart Contract |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Ether lost to orphan address |  | Weakness |  |  | Smart Contract |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Ethereum Gasless Send |  | Weakness |  |  | Smart Contract |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Floating Pragma |  | Weakness |  |  | Smart Contract |  | CWE-664: Improper Control of a Resource Through its Lifetime | https://swcregistry.io/docs/SWC-103 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Forcibly Sending Ether to a Contract |  | Weakness |  |  | Smart Contract |  |  | https://ethereum-contract-security-techniques-and-tips.readthedocs.io/en/latest/known_attacks/ |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Function Default Visibility |  | Weakness |  |  | Smart Contract |  | CWE-710: Improper Adherence to Coding Standards | https://swcregistry.io/docs/SWC-100 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Generating Randomness |  | Weakness | Generating randomness can be a uniquely difficult problem in certain computing environments that smart contracts execute within |  | Smart Contract |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Hash Collisions With Multiple Variable Length Arguments |  | Weakness |  |  | Smart Contract |  | CWE-294: Authentication Bypass by Capture-replay | https://swcregistry.io/docs/SWC-133 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Immutable Bugs |  | Weakness | DLT/Blockchains can include immutable data, protocols, smart contract implementations and so on, thus it is possible that a vulnerability can be found in a component that cannot be updated at all, or reasonably (e.g. it would require a governance decision or change to update) |  | Smart Contract |  |  |  |  |  |  |  |  |  |  |  |  | Smart Contract upgradeable contract |  |  | 
Smart Contract Incorrect Constructor Name |  | Weakness |  |  | Smart Contract |  | CWE-665: Improper Initialization | https://swcregistry.io/docs/SWC-118 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Incorrect ERC20 implementation |  | Weakness |  |  | Smart Contract |  |  | https://mythx.io/detectors/ |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Incorrect function state mutability |  | Weakness |  |  | Smart Contract |  |  | https://mythx.io/detectors/ |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Incorrect Inheritance Order |  | Weakness |  |  | Smart Contract |  | CWE-696: Incorrect Behavior Order | https://swcregistry.io/docs/SWC-125 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Insufficient Gas Griefing |  | Weakness |  |  | Smart Contract |  | CWE-691: Insufficient Control Flow Management | https://swcregistry.io/docs/SWC-126 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Integer Overflow and Underflow |  | Weakness | Many smart contract languages includes types that are susceptible to integer underflow and overflows |  | Smart Contract |  | CWE-682: Incorrect Calculation | https://swcregistry.io/docs/SWC-101 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Keeping Secrets | Smart Contract Secrecy failure | Weakness |  |  | Smart Contract |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Lack of Address Key Binding |  | Weakness | Addresses can be bound to keys, failure to do so can be problematic if short addresses are used (e.g. because an attacker can create a wallet with the same short address). |  |  |  |  | https://research.kudelskisecurity.com/2018/01/16/blockchains-how-to-steal-millions-in-264-operations/ |  |  |  |  |  |  |  |  |  | Smart Contract Short Address Attack |  |  | 
Smart Contract Lack of Proper Signature Verification |  | Weakness |  |  | Smart Contract |  | CWE-345: Insufficient Verification of Data Authenticity | https://swcregistry.io/docs/SWC-122 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Manipulated balance |  | Weakness |  |  | Smart Contract |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Message call with hardcoded gas amount |  | Weakness |  |  | Smart Contract |  | CWE-655: Improper Initialization | https://swcregistry.io/docs/SWC-134 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Mishandled Exceptions |  | Weakness |  |  | Smart Contract |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Missing Protection against Signature Replay Attacks |  | Weakness |  |  | Smart Contract |  | CWE-347: Improper Verification of Cryptographic Signature | https://swcregistry.io/docs/SWC-121 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Presence of unused variables |  | Weakness |  |  | Smart Contract |  | CWE-1164: Irrelevant Code | https://swcregistry.io/docs/SWC-131 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Race Conditions |  | Weakness |  |  | Smart Contract |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Reentrancy Race Condition |  | Weakness | Calling a function repeatedly before the first one(s) finish, allowing you to withdraw money repeatedly for example | Smart Contract Race Conditions | Smart Contract |  | CWE-663: Use of a Non-reentrant Function in a Concurrent Context CWE-841: Improper Enforcement of Behavioral Workflow | https://swcregistry.io/docs/SWC-107 https://consensys.github.io/smart-contract-best-practices/known_attacks/ https://ethereum.stackexchange.com/search?q=reentrancy   https://medium.com/coinmonks/reentrancy-exploit-ac5417086750 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Requirement Violation |  | Weakness |  |  | Smart Contract |  | CWE-573: Improper Following of Specification by Caller | https://swcregistry.io/docs/SWC-123 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Right-To-Left-Override control character (U+202E) |  | Weakness |  |  | Smart Contract |  | CWE-451: User Interface (UI) Misrepresentation of Critical Information | https://swcregistry.io/docs/SWC-130 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Shadowing State Variables |  | Weakness |  |  | Smart Contract |  | CWE-710: Improper Adherence to Coding Standards | https://swcregistry.io/docs/SWC-119 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Short Address Attack | Insufficient signature information, Smart Contract Short Addresses Attack | Weakness |  |  | Smart Contract |  | CWE-345 |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Signature Malleability |  | Weakness |  |  | Smart Contract |  | CWE-347: Improper Verification of Cryptographic Signature | https://swcregistry.io/docs/SWC-117 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Stack Size Limit |  | Weakness |  |  | Smart Contract |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract State Variable Default Visibility |  | Weakness |  |  | Smart Contract |  | CWE-710: Improper Adherence to Coding Standards | https://swcregistry.io/docs/SWC-108 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Timestamp Dependency |  | Weakness |  | Smart Contract Race Conditions | Smart Contract |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Transaction Order Dependence | Transaction ordering dependence | Weakness |  |  | Smart Contract |  | CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') | https://swcregistry.io/docs/SWC-114 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Transaction Ordering Dependency (TOD) |  | Weakness |  | Smart Contract Race Conditions | Smart Contract |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Typecasts |  | Weakness |  |  | Smart Contract |  | CWE-704, CWE-681, CWE-195 |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Typographical Error |  | Weakness |  |  | Smart Contract |  | CWE-480: Use of Incorrect Operator | https://swcregistry.io/docs/SWC-129 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Unchecked Call Return Value |  | Weakness |  |  | Smart Contract |  | CWE-252: Unchecked Return Value | https://swcregistry.io/docs/SWC-104 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Unchecked Return Values |  | Weakness |  |  | Smart Contract |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Underpriced opcodes |  | Weakness | If an opcode is improperly priced, e.g. it may be very computationally expensive to run but the gas cost to run it does not reflect t |  | Smart Contract |  |  |  | his an attacker can abuse it |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Unencrypted Private Data On-Chain |  | Weakness |  |  | Smart Contract |  | CWE-767: Access to Critical Private Variable via Public Method | https://swcregistry.io/docs/SWC-136 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract unexpected call return value |  | Weakness |  |  | Smart Contract |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Unexpected Ether balance |  | Weakness |  |  | Smart Contract |  | CWE-667: Improper Locking | https://swcregistry.io/docs/SWC-132 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Uninitialized Storage Pointer |  | Weakness |  |  | Smart Contract |  | CWE-824: Access of Uninitialized Pointer | https://swcregistry.io/docs/SWC-109 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Unpredictable State |  | Weakness |  |  | Smart Contract |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Unprotected Ether Withdrawal |  | Weakness |  |  | Smart Contract |  | CWE-284: Improper Access Control | https://swcregistry.io/docs/SWC-105 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Unprotected SELFDESTRUCT Instruction |  | Weakness |  |  | Smart Contract |  | CWE-284: Improper Access Control | https://swcregistry.io/docs/SWC-106 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Unprotected suicide |  | Weakness |  |  | Smart Contract |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract upgradeable contract |  | Weakness |  |  | Smart Contract |  |  | https://arxiv.org/pdf/1908.04507.pdf |  |  |  |  |  |  |  |  |  | Smart Contract Immutable Bugs |  |  | 
Smart Contract Usage of "continue" in "do-while" |  | Weakness |  |  | Smart Contract |  |  | https://mythx.io/detectors/ |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Use of Deprecated Solidity Functions |  | Weakness |  |  | Smart Contract |  | CWE-477: Use of Obsolete Function | https://swcregistry.io/docs/SWC-111 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Weak Field Modifier |  | Weakness |  |  | Smart Contract |  |  | https://medium.com/coinmonks/8-security-vulnerabilities-in-ethereum-smart-contracts-that-can-now-be-easily-avoided-dcb7de37a64 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Weak Sources of Randomness from Chain Attributes |  | Weakness |  | Smart Contract Generating Randomness | Smart Contract |  | CWE-330: Use of Insufficiently Random Values | https://swcregistry.io/docs/SWC-120 |  |  |  |  |  |  |  |  |  |  |  |  | 
Smart Contract Write to Arbitrary Storage Location |  | Weakness |  |  | Smart Contract |  | CWE-123: Write-what-where Condition | https://swcregistry.io/docs/SWC-124 |  |  |  |  |  |  |  |  |  |  |  |  | 
Soft Forks |  | Weakness |  |  | Multiple |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Sole Block Synchronization |  | Weakness |  |  | Blockchain Network Level |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Stealth addresses |  | Weakness |  |  | Cryptography |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Sybil Attacks |  | Weakness |  |  | Multiple |  |  |  |  |  |  |  |  |  |  |  |  |  | https://www.binance.vision/security/sybil-attacks-explained https://coincentral.com/sybil-attack-blockchain/ https://en.wikipedia.org/wiki/Sybil_attack |  | 
Time Manipulation |  | Weakness |  |  | Smart Contract |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Timebomb |  | Weakness |  |  | Consensus Protocols |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Timejacking |  | Weakness |  |  | Multiple |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Transaction Flooding |  | Weakness |  |  | Blockchain Network Level |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Transaction malleability |  | Weakness | Transaction malleability can occur when an attacker changes a transaction ID before confirmation on the blockchain/DLT network, making it possible for the attacker to pretend the transaction didn't happen, allowing for double deposits or withdrawls to happen with exchanges for example. |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Two-Factor Authentication (2FA) | 2FA | Defense |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Two-Factor Authentication (2FA) via Biometrics |  | Defense |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Two-Factor Authentication (2FA) via Email |  | Defense |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Two-Factor Authentication (2FA) via Hardware Token |  | Defense |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Two-Factor Authentication (2FA) via One Time Code |  | Defense |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Two-Factor Authentication (2FA) via Phone Call |  | Defense |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Two-Factor Authentication (2FA) via Physical Mail |  | Defense |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Two-Factor Authentication (2FA) via SMS |  | Defense |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Two-Factor Authentication (2FA) via Software Token |  | Defense |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Typo squatting on spellcheck names |  | Weakness | On platforms with spell check (e.g. mobile) the attacker picks a name and registers the version spell check suggests, any user entering the correct name which may then automatically get modified due to spell check ends up interacting with the attacker instead of the party they wanted to. |  | Multiple |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Uncle block rewards |  | Weakness | If uncle blocks are rewarded rthen miners may choose to mine uncle blocks improperly in order to gain rewards |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Uncle Forks |  | Weakness |  |  | Multiple |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Unlimited incoming connections |  | Weakness | If a system does not properly rate limit or expire new connections an attacker can easily cause a denial of service |  | Blockchain Network Level |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Vector76 |  | Weakness |  |  | Blockchain Network Level |  |  | https://arxiv.org/pdf/1605.09193.pdf |  |  |  |  |  |  |  |  |  |  |  |  | 
Voice Assistant Attack | SurfingAttack | Weakness | Use of ultrasonic/non audible audio to command voice assistant commands "SurfingAttack" |  | Multiple |  |  | DLTI-2020-04-07-4 |  |  |  |  |  |  |  |  |  |  |  |  | 
Vote Token trapping |  | Weakness | An attacker can create an election issues (for example using a contentious issue) to trick users into using their voting tokens which are then locked for a period of time, the attacker can then launch another election for something important and have a better chance of manipulating the outcome if many vote tokens are locked in other elections. |  | Multiple |  |  | DLTI-2016-06-22-1 |  |  |  |  |  |  |  |  |  |  |  |  | 
Vulnerabilities in virtual machines(EVM,JVM) |  | Weakness |  |  | Smart Contract |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Vulnerability to Malware |  | Weakness |  |  | Node User |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Vulnerable Signatures |  | Weakness |  |  | Wallet |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Wallet theft |  | Weakness | An attacker that can steal a wallet (e.g. the private keys used to control access to crypto assets) can then transfer/steal the assets. |  | Exchange, Wallet |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Wallet Weak seed creation |  | Weakness |  |  | Exchange, Wallet |  |  | DLTI-2020-02-04-1 |  |  |  |  |  |  |  |  |  |  |  |  | 
Zero Balance Accounts | Empty accounts | Defense | By creating a large number of zero balance accounts an attacker can consume a large amount of resources |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 
Bitcoin lightning - spamming payment micropayments |  | Weakness |  |  |  |  |  | https://www.coindesk.com/bitcoin-lightning-network-vulnerabilities-not-exploited-yet |  |  |  |  |  |  |  |  |  |  |  |  | 
Bitcoin lightning - flood and loot |  | Weakness |  |  |  |  |  | https://www.coindesk.com/bitcoin-lightning-network-vulnerabilities-not-exploited-yet |  |  |  |  |  |  |  |  |  |  |  |  | 
Bitcoin lightning - Eclipse Attack Time Dilation |  | Weakness |  |  |  |  |  | https://www.coindesk.com/bitcoin-lightning-network-vulnerabilities-not-exploited-yet |  |  |  |  |  |  |  |  |  |  |  |  | 
Bitcoin lightning - pinning |  | Weakness |  |  |  |  |  | https://www.coindesk.com/bitcoin-lightning-network-vulnerabilities-not-exploited-yet |  |  |  |  |  |  |  |  |  |  |  |  | 
