# merkle_multi_sig
This project implements a multi-signature wallet on the Solana blockchain using a Merkle tree to represent authorized signers. This approach provides an efficient and scalable solution for managing access control in multi-signature wallets. The project includes role-based access control, transaction queuing with time locks and tags, daily spend limits, and the ability to dynamically adjust the signing threshold.

devnet:(https://explorer.solana.com/address/5D4UouHzd758mf6qfUDRMrSGNEZKM3T7bgneWy5UoUa6?cluster=devnet)

## Features

- **Efficient multi-signature wallet**: Reduces on-chain storage by representing signers in a Merkle tree.
- **Flexible authorization**: Allows dynamically updating the signer set by changing the Merkle root.
- **Role-based access control (RBAC)**: Assigns roles such as INITIATOR, APPROVER, and ADMIN to each signer.
- **Transaction queuing**: Supports queuing transactions with time locks and tags for conditional execution.
- **Daily spend limits**: Imposes daily limits on SOL and SPL token transfers to enhance security.
- **Threshold adjustment**: Allows admins to change the signing threshold dynamically.
