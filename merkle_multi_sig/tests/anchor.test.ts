//TODO: FIX TEST FILE
//ONLY USE TEST FILE IF NEEDED
describe("Merkle Multi-Sig Wallet Tests", () => {
  let walletKp, receiverKp, newAccountKp;

  before(async () => {
    // Generate keypairs for the wallet, receiver, and a new account
    walletKp = new web3.Keypair();
    receiverKp = new web3.Keypair();
    newAccountKp = new web3.Keypair();
  });

  it("initializes the multi-sig wallet", async () => {
    const merkleRoot = Array(32).fill(0); // Merkle root as number[]
    const threshold = 2; // u8 as number
    const signersCount = 3; // u8 as number
    const expiration = new BN(86400); // i64 as BN
    const roleMapping = Buffer.from([0, 1, 2]); // Buffer for role mapping
    const signerWeights = Buffer.from([1, 1, 1]); // Buffer for signer weights
    const dailyLimitSol = new BN(1000000000); // u64 as BN (1 SOL)
    const dailyLimitSpl = new BN(500000000); // u64 as BN (0.5 SOL in SPL)

    const txHash = await pg.program.methods
      .initializeWallet(
        merkleRoot,
        threshold,
        signersCount,
        expiration,
        [pg.wallet.publicKey, receiverKp.publicKey, newAccountKp.publicKey],
        roleMapping,
        signerWeights,
        dailyLimitSol,
        dailyLimitSpl
      )
      .accounts({
        wallet: walletKp.publicKey,
        user: pg.wallet.publicKey,
        systemProgram: web3.SystemProgram.programId,
      })
      .signers([walletKp])
      .rpc();

    console.log(`Initialized wallet. Transaction hash: ${txHash}`);
  });

  it("queues a time-locked transaction", async () => {
    const timeLock = new BN(60); // 1 minute time lock
    const transactionData = Buffer.from("test transaction data"); // Example data
    const tag = "tx-tag";
    const reason = "Test reason for the transaction";

    const txHash = await pg.program.methods
      .queueTransactionWithTag(
        {
          /*
          Argument of type '[{ data: Buffer; timeLock: BN; }, string, "Test reason for the transaction"]' is not assignable to parameter of type 'ArgsTuple<[{ name: "transactionData"; type: "bytes"; }, { name: "timeLock"; type: "i64"; }, { name: "tag"; type: "string"; }, { name: "reason"; type: { option: "string"; }; }], DecodedHelper<unknown, EmptyDefined>>'.
  Type '[{ data: Buffer; timeLock: BN; }, string, "Test reason for the transaction"]' is not assignable to type '[Buffer, BN, string, string]'.
    Source has 3 element(s) but target requires 4.    */ 
    
          data: transactionData,
          timeLock: timeLock,
        }, // Struct format for TimeLockedTransaction
        tag,
        reason
      )
      .accounts({
        wallet: walletKp.publicKey,
        signer: pg.wallet.publicKey,
      })
      .rpc();

    console.log(`Queued transaction with tag '${tag}'. Transaction hash: ${txHash}`);
  });

  it("executes a transaction with token transfer", async () => {
    const proofs = [[Array(32).fill(0)], [Array(32).fill(0)]]; // Merkle proofs as number[][][]
    const leafHashes = [Array(32).fill(0), Array(32).fill(0)]; // Leaf hashes as number[][]
    const transactionData = Buffer.from("Execute this transaction");
    const tokenAmount = new BN(500000000); // SPL token amount (0.5 SPL)
    const solAmount = new BN(100000000); // SOL amount (0.1 SOL)
    const nonce = new BN(1);

    const txHash = await pg.program.methods
      .executeTransactionWithTokenTransfer(
        proofs,
        leafHashes,
        transactionData,
        tokenAmount,
        solAmount,
        nonce
      )
      .accounts({
        wallet: walletKp.publicKey,
        walletTokenAccount: newAccountKp.publicKey,
        receiver: receiverKp.publicKey,
        tokenProgram: splToken.TOKEN_PROGRAM_ID,
        signer: pg.wallet.publicKey,
      })
      .signers([walletKp])
      .rpc();

    console.log(`Executed transaction with token transfer. Transaction hash: ${txHash}`);
  });

  it("updates threshold by an admin", async () => {
    const newThreshold = 3; // Increase threshold to 3 signers

    const txHash = await pg.program.methods
      .updateThreshold(newThreshold)
      .accounts({
        wallet: walletKp.publicKey,
        signer: pg.wallet.publicKey, // Assuming this signer has admin role
      })
      .rpc();

    console.log(`Updated threshold to ${newThreshold}. Transaction hash: ${txHash}`);
  });
});
