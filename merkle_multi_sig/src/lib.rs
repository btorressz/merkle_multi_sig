use anchor_lang::prelude::*;
use anchor_lang::solana_program::keccak;
use anchor_spl::token::{self, Transfer, TokenAccount, Token};

declare_id!("5D4UouHzd758mf6qfUDRMrSGNEZKM3T7bgneWy5UoUa6");

pub const INITIATOR_ROLE: u8 = 0;
pub const APPROVER_ROLE: u8 = 1;
pub const ADMIN_ROLE: u8 = 2;

#[program]
pub mod merkle_multi_sig {
    use super::*;

    /// Initializes the multi-sig wallet with the given Merkle root and a signing threshold.
    pub fn initialize_wallet(
        ctx: Context<InitializeWallet>, 
        merkle_root: [u8; 32], 
        threshold: u8, 
        signers_count: u8, 
        expiration: i64,  // Default expiration time
        signer_keys: Vec<Pubkey>,  // Signer public keys
        role_mapping: Vec<u8>,     // Role mapping (1:1 with signer keys)
        signer_weights: Vec<u8>,   // Weight mapping for each signer (for weighted voting)
        daily_limit_sol: u64,
        daily_limit_spl: u64,
    ) -> Result<()> {
        let wallet = &mut ctx.accounts.wallet;
        wallet.merkle_root = merkle_root;
        wallet.threshold = threshold;
        wallet.signers_count = signers_count;
        wallet.executed = false;
        wallet.transaction_timestamp = Clock::get()?.unix_timestamp;
        wallet.expiration = expiration;
        wallet.executed_transactions = vec![];
        wallet.transaction_queue = vec![];
        wallet.transaction_tags = vec![];
        wallet.pending_transaction = None;
        wallet.rejected = false;
        wallet.signer_keys = signer_keys;
        wallet.role_mapping = role_mapping;
        wallet.signer_weights = signer_weights;
        wallet.nonces = vec![];
        wallet.daily_limit_sol = daily_limit_sol;
        wallet.daily_limit_spl = daily_limit_spl;
        wallet.daily_spent_sol = 0;
        wallet.daily_spent_spl = 0;
        wallet.last_spend_timestamp = Clock::get()?.unix_timestamp;

        // Emit an event to log the wallet initialization
        emit!(WalletInitialized {
            wallet: *ctx.accounts.wallet.to_account_info().key,
            merkle_root,
            threshold,
            signers_count,
        });

        Ok(())
    }

    /// Queues a transaction with a time-lock and tag
    pub fn queue_transaction_with_tag(
        ctx: Context<QueueTransaction>, 
        transaction_data: Vec<u8>, 
        time_lock: i64,
        tag: String,
        reason: Option<String>   // Added optional reason field
    ) -> Result<()> {
        let wallet = &mut ctx.accounts.wallet;
        wallet.transaction_queue.push((transaction_data.clone(), time_lock));
        wallet.transaction_tags.push((transaction_data, tag));

        if let Some(reason) = reason {
            msg!("Transaction queued with reason: {}", reason);   // Log the reason if provided
        }

        Ok(())
    }

    /// Processes all time-locked transactions
    pub fn process_time_locked_transactions(
        ctx: Context<ProcessTransactions>,
        proofs: Vec<Vec<[u8; 32]>>,
        leaf_hashes: Vec<[u8; 32]>,
    ) -> Result<()> {
        let wallet = &mut ctx.accounts.wallet;
        let current_time = Clock::get()?.unix_timestamp;

        for (tx_data, lock_time) in wallet.transaction_queue.iter() {
            if current_time >= *lock_time {
                let total_weight = verify_signatures_with_weights(wallet, proofs.clone(), leaf_hashes.clone())?;
                if total_weight >= wallet.threshold {
                    msg!("Processing time-locked transaction...");
                    // Execute transaction logic here
                } else {
                    return Err(ErrorCode::NotEnoughSignatures.into());
                }
            }
        }

        // Clear the queue after execution
        wallet.transaction_queue.clear();

        Ok(())
    }

    /// Processes transactions by tag
    pub fn process_transactions_by_tag(
        ctx: Context<ProcessTransactionsByTag>, 
        tag: String, 
        proofs: Vec<Vec<[u8; 32]>>, 
        leaf_hashes: Vec<[u8; 32]>
    ) -> Result<()> {
        let wallet = &mut ctx.accounts.wallet;

        // Process only transactions with the specified tag
        for (tx_data, tx_tag) in wallet.transaction_tags.iter() {
            if tx_tag == &tag {
                let total_weight = verify_signatures_with_weights(wallet, proofs.clone(), leaf_hashes.clone())?;
                if total_weight >= wallet.threshold {
                    msg!("Processing tagged transaction: {}", tx_tag);
                    // Execute transaction logic here
                } else {
                    return Err(ErrorCode::NotEnoughSignatures.into());
                }
            }
        }

        Ok(())
    }

    /// Reimburses transaction fee to the fee payer after execution
    pub fn reimburse_transaction_fee(ctx: Context<ReimburseFee>, transaction_fee: u64) -> Result<()> {
        let wallet = &mut ctx.accounts.wallet;

        // Ensure there are enough funds to reimburse the fee
        if **ctx.accounts.wallet.to_account_info().lamports.borrow() < transaction_fee {
            return Err(ErrorCode::InsufficientFunds.into());
        }

        // Reimburse the fee to the fee payer
        let fee_payer = &ctx.accounts.fee_payer;
        **fee_payer.lamports.borrow_mut() += transaction_fee;

        msg!("Reimbursed transaction fee: {} lamports", transaction_fee);
        Ok(())
    }

    /// Updates the threshold dynamically, only by an admin.
    pub fn update_threshold(ctx: Context<UpdateThreshold>, new_threshold: u8) -> Result<()> {
        let wallet = &mut ctx.accounts.wallet;

        // Ensure the caller has the admin role
        let signer_index = get_signer_index(ctx.accounts.signer.key, wallet)?;
        check_role(wallet, ADMIN_ROLE, signer_index)?;

        // Rate limit the admin actions by time
        let current_time = Clock::get()?.unix_timestamp;
        if current_time - wallet.last_spend_timestamp < 86400 {
            return Err(ErrorCode::AdminActionRateLimited.into());   // Rate limiting: one action per day
        }
        wallet.last_spend_timestamp = current_time;

        // Ensure the new threshold is valid
        if new_threshold > wallet.signers_count {
            return Err(ErrorCode::InvalidThreshold.into());
        }

        wallet.threshold = new_threshold;

        // Emit an event for threshold update
        emit!(ThresholdUpdated {
            wallet: *ctx.accounts.wallet.to_account_info().key,
            new_threshold,
        });

        Ok(())
    }

    /// Executes a transaction with provided Merkle proofs and transfers tokens (both SOL and SPL tokens).
    pub fn execute_transaction_with_token_transfer(
        ctx: Context<ExecuteTokenTransfer>,
        proofs: Vec<Vec<[u8; 32]>>,  // Each signer submits a list of hashes for Merkle proof
        leaf_hashes: Vec<[u8; 32]>,  // Corresponding leaf hashes (signer's public key hash)
        transaction_data: Vec<u8>,   // Data for the transaction (this is customizable)
        token_amount: u64,           // Amount of SPL tokens to transfer
        native_sol_amount: u64,      // Amount of SOL to transfer
        nonce: u64                   // Nonce to prevent replay attacks
    ) -> Result<()> {
        // Extract immutable references for transfer accounts
        let wallet_account_info = ctx.accounts.wallet.to_account_info();
        let receiver_account_info = ctx.accounts.receiver.to_account_info();

        let wallet = &mut ctx.accounts.wallet;

        // Check if transaction has been rejected
        if wallet.rejected {
            return Err(ErrorCode::TransactionAlreadyRejected.into());
        }

        // Check if transaction has expired
        let current_time = Clock::get()?.unix_timestamp;
        if wallet.transaction_timestamp + wallet.expiration < current_time {
            return Err(ErrorCode::TransactionExpired.into());
        }

        // Check if transaction has already been executed
        if wallet.executed {
            return Err(ErrorCode::TransactionAlreadyExecuted.into());
        }

        // Check if nonce has already been used
        if wallet.nonces.contains(&nonce) {
            return Err(ErrorCode::NonceAlreadyUsed.into());
        }

        // Check daily limits
        check_daily_limit(wallet, native_sol_amount, token_amount)?;

        // Verify signatures
        let mut valid_signatures = 0;
        for i in 0..proofs.len() {
            let proof = &proofs[i];
            let leaf = leaf_hashes[i];

            // Check if signer has the necessary role (e.g., approver)
            let signer_role = wallet.role_mapping[i];
            if signer_role != APPROVER_ROLE {
                msg!("Invalid role for signer: {}. Approver role required.", i);   // Detailed error log
                return Err(ErrorCode::InvalidRole.into());
            }

            if verify_merkle_proof(leaf, proof, wallet.merkle_root) {
                valid_signatures += 1;
            }
        }

        // Ensure the threshold is met
        if valid_signatures >= wallet.threshold {
            wallet.executed = true;
            wallet.nonces.push(nonce); // Add nonce to prevent replay attacks

            // Transfer SOL if specified
            if native_sol_amount > 0 {
                **receiver_account_info.lamports.borrow_mut() += native_sol_amount;
                wallet.daily_spent_sol += native_sol_amount; // Update daily spend
            }

            // Transfer SPL tokens if needed
            if token_amount > 0 {
                let cpi_accounts = Transfer {
                    from: ctx.accounts.wallet_token_account.to_account_info(),
                    to: receiver_account_info.clone(),
                    authority: wallet_account_info.clone(),
                };
                let cpi_program = ctx.accounts.token_program.to_account_info();
                let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
                token::transfer(cpi_ctx, token_amount)?;
                wallet.daily_spent_spl += token_amount; // Update daily spend
            }

            // Log transaction execution
            wallet.executed_transactions.push(keccak::hashv(&[&transaction_data]).to_bytes());

            // Emit an event to log the transaction execution
            emit!(TransactionExecuted {
                wallet: *wallet_account_info.key,
                transaction_data: transaction_data.clone(),
                signatures_count: valid_signatures,
            });
        } else {
            return Err(ErrorCode::NotEnoughSignatures.into());
        }

        Ok(())
    }

    /// Rejects the pending transaction.
    pub fn reject_transaction(ctx: Context<RejectTransaction>) -> Result<()> {
        let wallet = &mut ctx.accounts.wallet;

        if wallet.rejected {
            return Err(ErrorCode::TransactionAlreadyRejected.into());
        }

        wallet.rejected = true;

        emit!(TransactionRejected {
            wallet: *ctx.accounts.wallet.to_account_info().key,
        });

        Ok(())
    }
}

/// Get the signer's index in the signer keys array.
fn get_signer_index(signer_key: &Pubkey, wallet: &Wallet) -> Result<usize> {
    let signer_index = wallet
        .signer_keys
        .iter()
        .position(|key| key == signer_key)
        .ok_or(ErrorCode::InvalidSigner)?;

    Ok(signer_index)
}

/// Check if a signer has the required role.
fn check_role(wallet: &Wallet, required_role: u8, signer_index: usize) -> Result<()> {
    if wallet.role_mapping[signer_index] != required_role {
        return Err(ErrorCode::InvalidRole.into());
    }
    Ok(())
}

/// Check daily limit for SOL and SPL tokens.
fn check_daily_limit(wallet: &mut Wallet, sol_amount: u64, spl_amount: u64) -> Result<()> {
    let current_time = Clock::get()?.unix_timestamp;

    // Reset daily spending if a new day has started
    if current_time - wallet.last_spend_timestamp >= 86400 {
        wallet.daily_spent_sol = 0;
        wallet.daily_spent_spl = 0;
        wallet.last_spend_timestamp = current_time;
    }

    // Check if the transaction exceeds the daily limits
    if wallet.daily_spent_sol + sol_amount > wallet.daily_limit_sol {
        msg!(
            "SOL limit exceeded. Spent today: {}, attempted: {}, limit: {}",
            wallet.daily_spent_sol,
            sol_amount,
            wallet.daily_limit_sol
        );
        return Err(ErrorCode::DailyLimitExceeded.into());
    }
    if wallet.daily_spent_spl + spl_amount > wallet.daily_limit_spl {
        msg!(
            "SPL limit exceeded. Spent today: {}, attempted: {}, limit: {}",
            wallet.daily_spent_spl,
            spl_amount,
            wallet.daily_limit_spl
        );
        return Err(ErrorCode::DailyLimitExceeded.into());
    }

    Ok(())
}

/// Verifies a Merkle proof given the leaf, proof, and the Merkle root.
fn verify_merkle_proof(leaf: [u8; 32], proof: &Vec<[u8; 32]>, root: [u8; 32]) -> bool {
    let mut computed_hash = leaf;

    for hash in proof.iter() {
        computed_hash = if computed_hash < *hash {
            keccak::hashv(&[&computed_hash, hash]).to_bytes()
        } else {
            keccak::hashv(&[hash, &computed_hash]).to_bytes()
        };
    }

    computed_hash == root
}

/// Verify signatures with weighted voting.
fn verify_signatures_with_weights(wallet: &Wallet, proofs: Vec<Vec<[u8; 32]>>, leaf_hashes: Vec<[u8; 32]>) -> Result<u8> {
    let mut total_weight = 0;

    for i in 0..proofs.len() {
        let proof = &proofs[i];
        let leaf = leaf_hashes[i];

        if verify_merkle_proof(leaf, proof, wallet.merkle_root) {
            total_weight += wallet.signer_weights[i];
        }
    }

    Ok(total_weight)
}

#[account]
pub struct Wallet {
    pub merkle_root: [u8; 32],
    pub threshold: u8,
    pub signers_count: u8,
    pub executed: bool,
    pub transaction_timestamp: i64,
    pub expiration: i64,
    pub executed_transactions: Vec<[u8; 32]>,
    pub pending_transaction: Option<[u8; 32]>,
    pub rejected: bool,
    pub transaction_queue: Vec<(Vec<u8>, i64)>,   // Transactions with time-locks
    pub transaction_tags: Vec<(Vec<u8>, String)>, // Transactions with tags
    pub signer_keys: Vec<Pubkey>,                 // Signer public keys
    pub role_mapping: Vec<u8>,                    // Role mapping for each signer
    pub signer_weights: Vec<u8>,                  // Weight for each signer
    pub nonces: Vec<u64>,
    pub daily_limit_sol: u64,
    pub daily_limit_spl: u64,
    pub daily_spent_sol: u64,
    pub daily_spent_spl: u64,
    pub last_spend_timestamp: i64,
}

#[derive(Accounts)]
pub struct InitializeWallet<'info> {
    #[account(init, payer = user, space = 8 + 256)]
    pub wallet: Account<'info, Wallet>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct QueueTransaction<'info> {
    #[account(mut)]
    pub wallet: Account<'info, Wallet>,
    pub signer: Signer<'info>,
}

#[derive(Accounts)]
pub struct ProcessTransactions<'info> {
    #[account(mut)]
    pub wallet: Account<'info, Wallet>,
    pub signer: Signer<'info>,
}

#[derive(Accounts)]
pub struct ProcessTransactionsByTag<'info> {
    #[account(mut)]
    pub wallet: Account<'info, Wallet>,
    pub signer: Signer<'info>,
}

#[derive(Accounts)]
pub struct ReimburseFee<'info> {
    #[account(mut)]
    pub wallet: Account<'info, Wallet>,
    #[account(mut)]
    pub fee_payer: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdateThreshold<'info> {
    #[account(mut)]
    pub wallet: Account<'info, Wallet>,
    pub signer: Signer<'info>,
}

#[derive(Accounts)]
pub struct ExecuteTokenTransfer<'info> {
    #[account(mut)]
    pub wallet: Account<'info, Wallet>,
    #[account(mut)]
    pub wallet_token_account: Account<'info, TokenAccount>,
    #[account(mut)]
    pub receiver: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
    pub signer: Signer<'info>,
}

#[derive(Accounts)]
pub struct RejectTransaction<'info> {
    #[account(mut)]
    pub wallet: Account<'info, Wallet>,
    pub signer: Signer<'info>,
}

#[event]
pub struct WalletInitialized {
    pub wallet: Pubkey,
    pub merkle_root: [u8; 32],
    pub threshold: u8,
    pub signers_count: u8,
}

#[event]
pub struct ThresholdUpdated {
    pub wallet: Pubkey,
    pub new_threshold: u8,
}

#[event]
pub struct TransactionExecuted {
    pub wallet: Pubkey,
    pub transaction_data: Vec<u8>,
    pub signatures_count: u8,
}

#[event]
pub struct TransactionRejected {
    pub wallet: Pubkey,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Not enough valid signatures to execute transaction.")]
    NotEnoughSignatures,
    #[msg("Transaction has already been executed.")]
    TransactionAlreadyExecuted,
    #[msg("Transaction has expired.")]
    TransactionExpired,
    #[msg("Transaction has already been rejected.")]
    TransactionAlreadyRejected,
    #[msg("Nonce has already been used.")]
    NonceAlreadyUsed,
    #[msg("Signer does not have the required role for this action.")]
    InvalidRole,
    #[msg("Daily spending limit exceeded.")]
    DailyLimitExceeded,
    #[msg("Invalid threshold.")]
    InvalidThreshold,
    #[msg("Invalid signer.")]
    InvalidSigner,
    #[msg("Insufficient funds for fee reimbursement.")]
    InsufficientFunds,
    #[msg("Admin actions are rate-limited.")]
    AdminActionRateLimited,
}
