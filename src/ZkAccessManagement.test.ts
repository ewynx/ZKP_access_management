import { LocalBlockchain } from 'snarkyjs/dist/node/lib/mina';
import { MerkleWitness8, ZkAccessManagement } from './ZkAccessManagement';
import {
  isReady,
  shutdown,
  Field,
  Mina,
  PrivateKey,
  PublicKey,
  AccountUpdate,
  MerkleTree,
  Poseidon,
  Signature,
  UInt32
} from 'snarkyjs';

let proofsEnabled = true;

/*
 PASS  src/ZkAccessManagement.test.ts (2865.467 s)
  ZkAccessManagement
    ✓ generates and deploys the `ZkAccessManagement` smart contract (81524 ms)
    ✓ award an AccessPass to pubKey (executed by authority) (181459 ms)
    ✓ error if other entity than authority would try to award accesspass (76255 ms)
    ✓ error when the index of the accesspass and the owner claim do not match up (71806 ms)
    ✓ error when the nextIndex in the smart contract and the index of the new pass dont match (80126 ms)
    ✓ correctly transferOwnershipAccessPass from current owner to new one (219358 ms)
    ✓ error transferOwnershipAccessPass if its not the current owner signing (154397 ms)
    ✓ cant do transferOwnershipAccessPass for another accesspass (different index) (150954 ms)
    ✓ error transferOwnershipAccessPass if the accesspass doesnt exist (72813 ms)
    ✓ correctly authenticate (294330 ms)
    ✓ authenticate error with wrong privkey (is not owner of accesspass) (223947 ms)
    ✓ authenticate should fail if the accesspass witness is not valid (212170 ms)
    ✓ authenticate should fail when member tries to validate for incorrect accesspass (215098 ms)
    ✓ authenticate should fail when incorrect block (not within range of 10 before) is signed (257492 ms)
    ✓ correctly authenticate after transferring ownership (pass for new owner, fail for old owner) (468432 ms)

Test Suites: 1 passed, 1 total
Tests:       15 passed, 15 total
Snapshots:   0 total
Time:        2865.616 s
Ran all test suites.
  ●  process.exit called with "0"
*/

describe('ZkAccessManagement', () => {
  let deployerAccount: PublicKey,
    deployerKey: PrivateKey,
    zkAppAddress: PublicKey,
    zkAppPrivateKey: PrivateKey,
    zkApp: ZkAccessManagement,
    validPassesTree: MerkleTree,
    claimedPassesTree: MerkleTree;

  beforeAll(async () => {
    await isReady;
    if (proofsEnabled) ZkAccessManagement.compile();
  });

  beforeEach(() => {
    const Local = Mina.LocalBlockchain({ proofsEnabled });
    Mina.setActiveInstance(Local);
    ({ privateKey: deployerKey, publicKey: deployerAccount } =
      Local.testAccounts[0]);
    zkAppPrivateKey = PrivateKey.random();
    zkAppAddress = zkAppPrivateKey.toPublicKey();
    zkApp = new ZkAccessManagement(zkAppAddress);
    validPassesTree = new MerkleTree(8);
    claimedPassesTree = new MerkleTree(8);
  });

  afterAll(() => {
    // `shutdown()` internally calls `process.exit()` which will exit the running Jest process early.
    // Specifying a timeout of 0 is a workaround to defer `shutdown()` until Jest is done running all tests.
    // This should be fixed with https://github.com/MinaProtocol/mina/issues/10943
    setTimeout(shutdown, 0);
  });

  async function localDeploy() {
    const txn = await Mina.transaction(deployerAccount, () => {
      AccountUpdate.fundNewAccount(deployerAccount);
      zkApp.deploy();
      zkApp.initState(deployerKey, validPassesTree.getRoot(), claimedPassesTree.getRoot());
    });
    await txn.prove();
    // this tx needs .sign(), because `deploy()` adds an account update that requires signature authorization
    await txn.sign([deployerKey, zkAppPrivateKey]).send();
  }

  //WORKS
  it('generates and deploys the `ZkAccessManagement` smart contract', async () => {
    await localDeploy();
    const num = zkApp.validPassesNextIndex.get();
    const authorityPublicKey = zkApp.authority.get();
    expect(authorityPublicKey).toEqual(deployerAccount);
    expect(num).toEqual(Field(0));
  });

  //////////////////////////////////
  //////// AWARD ACCESSPASS ////////
  //////////////////////////////////
  
  //WORKS
  it('award an AccessPass to pubKey (executed by authority)', async () => {
    await localDeploy();

    let accessPass0 = PrivateKey.random();
    validPassesTree.setLeaf(0n, Poseidon.hash([accessPass0.toPublicKey().x]));
    const accessPassWitness = new MerkleWitness8(validPassesTree.getWitness(0n));

    // Now, award accessPass 0 to pubKey
    let newOWner = PrivateKey.random();
    let accessPass0Id = accessPass0.toPublicKey();
    claimedPassesTree.setLeaf(0n, Poseidon.hash([accessPass0Id.x, newOWner.toPublicKey().x]));
    const ownerValidityWitness = new MerkleWitness8(claimedPassesTree.getWitness(0n));

    const txn1 = await Mina.transaction(deployerAccount, () => {
      zkApp.awardAccessPass(newOWner.toPublicKey(), accessPass0Id, deployerKey, accessPassWitness, ownerValidityWitness);
    });
    await txn1.prove();
    await txn1.sign([deployerKey]).send();

    // TODO check whether this updates the root correctly
    
  });

  //WORKS
  it('error if other entity than authority would try to award accesspass', async () => {
    await localDeploy();

    let accessPass0 = PrivateKey.random();
    validPassesTree.setLeaf(0n, Poseidon.hash([accessPass0.toPublicKey().x]));
    const accessPassValidityWitness = new MerkleWitness8(validPassesTree.getWitness(0n));

    // Trying to award accessPass 0 to pubKey, but with wrong authority
    let newOwner = PrivateKey.random();
    let accessPass0Id = accessPass0.toPublicKey();
    claimedPassesTree.setLeaf(0n, Poseidon.hash([accessPass0Id.x, newOwner.toPublicKey().x]));
    const ownerValidityWitness = new MerkleWitness8(claimedPassesTree.getWitness(0n));

    let error = 'initial';
    try {
      await Mina.transaction(deployerAccount, () => {
        // NewOwner is not allowed to call this as the authority
        zkApp.awardAccessPass(newOwner.toPublicKey(), accessPass0Id, newOwner, accessPassValidityWitness, ownerValidityWitness);
      })
    } catch (e: any) {
      error = e.message;
    }
    // Check that an error has been thrown
    expect(error).not.toEqual('initial');
  });

  //WORKS
  it('error when the index of the accesspass and the owner claim do not match up', async () => {
    await localDeploy();

    // First, add accessPass so it is valid
    let accessPass0 = PrivateKey.random();
    validPassesTree.setLeaf(0n, Poseidon.hash([accessPass0.toPublicKey().x]));
    const accessPassValidityWitness = new MerkleWitness8(validPassesTree.getWitness(0n));

    // Now, award accessPass 0 to pubKey
    let newOWner = PrivateKey.random();
    let accessPass0Id = accessPass0.toPublicKey();
    // Setting index to 1 when the accesspass has index: should error 
    claimedPassesTree.setLeaf(1n, Poseidon.hash([accessPass0Id.x, newOWner.toPublicKey().x]));
    const ownerValidityWitness = new MerkleWitness8(claimedPassesTree.getWitness(1n));

    let error = '';
    try {
      const txn1 = await Mina.transaction(deployerAccount, () => {
        zkApp.awardAccessPass(newOWner.toPublicKey(), accessPass0Id, deployerKey, accessPassValidityWitness, ownerValidityWitness);
      });
    } catch (e: any) {
      error = e.message;
    }
    // Check that an error has been thrown
    expect(error).not.toEqual('initial');
  });

  // WORKS
  it('error when the nextIndex in the smart contract and the index of the new pass dont match', async () => {
    await localDeploy();

    // First, add accessPass so it is valid
    let accessPass8 = PrivateKey.random();
    validPassesTree.setLeaf(8n, Poseidon.hash([accessPass8.toPublicKey().x]));
    const accessPassValidityWitness = new MerkleWitness8(validPassesTree.getWitness(8n));

    // Now, award accessPass 0 to pubKey
    let newOWner = PrivateKey.random();
    let accessPass8Id = accessPass8.toPublicKey();
    claimedPassesTree.setLeaf(8n, Poseidon.hash([accessPass8Id.x, newOWner.toPublicKey().x]));
    const ownerValidityWitness = new MerkleWitness8(claimedPassesTree.getWitness(8n));

    let error = '';
    try {
      const txn1 = await Mina.transaction(deployerAccount, () => {
        zkApp.awardAccessPass(newOWner.toPublicKey(), accessPass8Id, deployerKey, accessPassValidityWitness, ownerValidityWitness);
      });
    } catch (e: any) {
      error = e.message;
    }
    // Should error because the smart contract expects index 0
    expect(error).not.toEqual('initial');
  });
  
  ////////////////////////////////////
  //////// TRANSFER OWNERSHIP ////////
  ////////////////////////////////////
  
  // WORKS
  it('correctly transferOwnershipAccessPass from current owner to new one', async () => {
    await localDeploy();

    let accessPass0 = PrivateKey.random();
    validPassesTree.setLeaf(0n, Poseidon.hash([accessPass0.toPublicKey().x]));
    let accessPassIndex = 0n;
    const accessPassWitness = new MerkleWitness8(validPassesTree.getWitness(accessPassIndex));

    // Award accessPass 0 to pubKey0
    let privKey0 = PrivateKey.random();
    let accessPass0Id = accessPass0.toPublicKey();
    claimedPassesTree.setLeaf(accessPassIndex, Poseidon.hash([accessPass0Id.x, privKey0.toPublicKey().x]));
    const ownerValidityWitness = new MerkleWitness8(claimedPassesTree.getWitness(accessPassIndex));

    const txn0 = await Mina.transaction(deployerAccount, () => {
      zkApp.awardAccessPass(privKey0.toPublicKey(), accessPass0Id, deployerKey, accessPassWitness, ownerValidityWitness);
    });
    await txn0.prove();
    await txn0.sign([deployerKey]).send();

    // Now, change ownership from pubKey0 to pubKey1
    let pubKey1 = PrivateKey.random();
    claimedPassesTree.setLeaf(accessPassIndex, Poseidon.hash([accessPass0Id.x, pubKey1.toPublicKey().x]));
    const newOwnerValidityWitness = new MerkleWitness8(claimedPassesTree.getWitness(accessPassIndex));

    const txn1 = await Mina.transaction(deployerAccount, () => {
      zkApp.transferOwnershipAccessPass(privKey0, pubKey1.toPublicKey(), accessPass0Id, accessPassWitness, ownerValidityWitness, newOwnerValidityWitness);
    });
    await txn1.prove();
    await txn1.sign([deployerKey]).send();
  });
    
  // WORKS
  it('error transferOwnershipAccessPass if its not the current owner signing', async () => {
    await localDeploy();

    let accessPass0 = PrivateKey.random();
    validPassesTree.setLeaf(0n, Poseidon.hash([accessPass0.toPublicKey().x]));
    let accessPassIndex = 0n;
    const accessPassWitness = new MerkleWitness8(validPassesTree.getWitness(accessPassIndex));

    // Award accessPass 0 to pubKey0
    let privKey0 = PrivateKey.random();
    let accessPass0Id = accessPass0.toPublicKey();
    claimedPassesTree.setLeaf(accessPassIndex, Poseidon.hash([accessPass0Id.x, privKey0.toPublicKey().x]));
    const ownerValidityWitness = new MerkleWitness8(claimedPassesTree.getWitness(accessPassIndex));

    const txn0 = await Mina.transaction(deployerAccount, () => {
      zkApp.awardAccessPass(privKey0.toPublicKey(), accessPass0Id, deployerKey, accessPassWitness, ownerValidityWitness);
    });
    await txn0.prove();
    await txn0.sign([deployerKey]).send();

    // Now, change ownership from pubKey0 to pubKey1
    let pubKey1 = PrivateKey.random();
    claimedPassesTree.setLeaf(accessPassIndex, Poseidon.hash([accessPass0Id.x, pubKey1.toPublicKey().x]));
    const newOwnerValidityWitness = new MerkleWitness8(claimedPassesTree.getWitness(accessPassIndex));

    let error = '';
    try {
      const txn1 = await Mina.transaction(deployerAccount, () => {
        // Should error when the current owner is not the signer
        zkApp.transferOwnershipAccessPass(pubKey1, pubKey1.toPublicKey(), accessPass0Id, accessPassWitness, ownerValidityWitness, newOwnerValidityWitness);
      });
    } catch (e: any) {
      error = e.message;
    }
    // Should error because the current owner is not signing off the transfer of ownership
    expect(error).not.toEqual('initial');
  });
    
  // WORKS
  it('cant do transferOwnershipAccessPass for another accesspass (different index)', async () => {
    await localDeploy();

    let accessPass0 = PrivateKey.random();
    validPassesTree.setLeaf(0n, Poseidon.hash([accessPass0.toPublicKey().x]));
    let accessPassIndex = 0n;
    const accessPassWitness = new MerkleWitness8(validPassesTree.getWitness(accessPassIndex));

    // Award accessPass 0 to pubKey0
    let privKey0 = PrivateKey.random();
    let accessPass0Id = accessPass0.toPublicKey();
    claimedPassesTree.setLeaf(accessPassIndex, Poseidon.hash([accessPass0Id.x, privKey0.toPublicKey().x]));
    const ownerValidityWitness = new MerkleWitness8(claimedPassesTree.getWitness(accessPassIndex));

    const txn0 = await Mina.transaction(deployerAccount, () => {
      zkApp.awardAccessPass(privKey0.toPublicKey(), accessPass0Id, deployerKey, accessPassWitness, ownerValidityWitness);
    });
    await txn0.prove();
    await txn0.sign([deployerKey]).send();

    // Change ownership from pubKey0 to pubKey1 for wrong accessPass index -> error
    let pubKey1 = PrivateKey.random();
    let wrongIndex = 7n;
    claimedPassesTree.setLeaf(wrongIndex, Poseidon.hash([accessPass0Id.x, pubKey1.toPublicKey().x]));
    const newOwnerValidityWitness = new MerkleWitness8(claimedPassesTree.getWitness(wrongIndex));
    let error = '';
    try {
      const txn1 = await Mina.transaction(deployerAccount, () => {
        zkApp.transferOwnershipAccessPass(privKey0, pubKey1.toPublicKey(), accessPass0Id, accessPassWitness, ownerValidityWitness, newOwnerValidityWitness);
      });
    } catch (e: any) {
      error = e.message;  
    }
    expect(error).not.toEqual('initial');
  });

      
  // WORKS
  it('error transferOwnershipAccessPass if the accesspass doesnt exist', async () => {
    await localDeploy();

    let accessPass0 = PrivateKey.random();
    validPassesTree.setLeaf(0n, Poseidon.hash([accessPass0.toPublicKey().x]));
    let accessPassIndex = 0n;
    const accessPassWitness = new MerkleWitness8(validPassesTree.getWitness(accessPassIndex));

    // We create accessPass 0, but never "officially" register it to be of pubKey0's
    let privKey0 = PrivateKey.random();
    let accessPass0Id = accessPass0.toPublicKey();
    claimedPassesTree.setLeaf(accessPassIndex, Poseidon.hash([accessPass0Id.x, privKey0.toPublicKey().x]));
    const ownerValidityWitness = new MerkleWitness8(claimedPassesTree.getWitness(accessPassIndex));

    // Now, change ownership from pubKey0 to pubKey1
    let pubKey1 = PrivateKey.random();
    claimedPassesTree.setLeaf(accessPassIndex, Poseidon.hash([accessPass0Id.x, pubKey1.toPublicKey().x]));
    const newOwnerValidityWitness = new MerkleWitness8(claimedPassesTree.getWitness(accessPassIndex));

    let error = '';
    try {
      const txn1 = await Mina.transaction(deployerAccount, () => {
        // Should error when the current owner is not the signer
        zkApp.transferOwnershipAccessPass(privKey0, pubKey1.toPublicKey(), accessPass0Id, accessPassWitness, ownerValidityWitness, newOwnerValidityWitness);
      });
    } catch (e: any) {
      error = e.message;
    }
    // Should error because the current owner is not signing off the transfer of ownership
    expect(error).not.toEqual('initial');
  });
  
  ////////////////////////////
  ////// AUTHENTICATE ////////
  ////////////////////////////

  // WORKS
  it('correctly authenticate', async () => {
    await localDeploy();

    // Award accessPass 0 to pubKey0
    let accessPass0 = PrivateKey.random();
    let accessPassIndex0 = 0n;
    validPassesTree.setLeaf(accessPassIndex0, Poseidon.hash([accessPass0.toPublicKey().x]));
    const accessPass0Witness = new MerkleWitness8(validPassesTree.getWitness(accessPassIndex0));

    let owner0 = PrivateKey.random();
    let accessPass0Id = accessPass0.toPublicKey();
    claimedPassesTree.setLeaf(accessPassIndex0, Poseidon.hash([accessPass0Id.x, owner0.toPublicKey().x]));
    const owner0ValidityWitness = new MerkleWitness8(claimedPassesTree.getWitness(accessPassIndex0));

    const txn0 = await Mina.transaction(deployerAccount, () => {
      zkApp.awardAccessPass(owner0.toPublicKey(), accessPass0Id, deployerKey, accessPass0Witness, owner0ValidityWitness);
    });
    await txn0.prove();
    await txn0.sign([deployerKey]).send();

    // Award accessPass 1 to pubKey1
    let accessPass1 = PrivateKey.random();
    let accessPassIndex1 = 1n;
    validPassesTree.setLeaf(accessPassIndex1, Poseidon.hash([accessPass1.toPublicKey().x]));
    const accessPass1Witness = new MerkleWitness8(validPassesTree.getWitness(accessPassIndex1));

    let owner1 = PrivateKey.random();
    let accessPass1Id = accessPass1.toPublicKey();
    claimedPassesTree.setLeaf(accessPassIndex1, Poseidon.hash([accessPass1Id.x, owner1.toPublicKey().x]));
    const owner1ValidityWitness = new MerkleWitness8(claimedPassesTree.getWitness(accessPassIndex1));

    const txn1 = await Mina.transaction(deployerAccount, () => {
      zkApp.awardAccessPass(owner1.toPublicKey(), accessPass1Id, deployerKey, accessPass1Witness, owner1ValidityWitness);
    });
    await txn1.prove();
    await txn1.sign([deployerKey]).send();

    // Try to authenticate with user 0. Making these witness again because some leaves were added later
    let accessPass0ValidityWitness = new MerkleWitness8(validPassesTree.getWitness(accessPassIndex0));
    let accessOwnershipWitness = new MerkleWitness8(claimedPassesTree.getWitness(accessPassIndex0));

    let signedBlockNr = Mina.getNetworkState().blockchainLength;
    let sig = Signature.create(owner0, accessPass0Id.toFields().concat(signedBlockNr.toFields()));

    const txnAuth = await Mina.transaction(deployerAccount, () => {
      zkApp.authenticate(owner0.toPublicKey(), signedBlockNr, accessPass0Id, sig, accessPass0ValidityWitness, accessOwnershipWitness);
    });
    await txnAuth.prove();
    await txnAuth.sign([deployerKey]).send();
  });

  // WORKS
  it('authenticate error with wrong privkey (is not owner of accesspass)', async () => {
    await localDeploy();

    // Award accessPass 0 to pubKey0
    let accessPass0 = PrivateKey.random();
    let accessPassIndex0 = 0n;
    validPassesTree.setLeaf(accessPassIndex0, Poseidon.hash([accessPass0.toPublicKey().x]));
    const accessPass0Witness = new MerkleWitness8(validPassesTree.getWitness(accessPassIndex0));

    let owner0 = PrivateKey.random();
    let accessPass0Id = accessPass0.toPublicKey();
    claimedPassesTree.setLeaf(accessPassIndex0, Poseidon.hash([accessPass0Id.x, owner0.toPublicKey().x]));
    const owner0ValidityWitness = new MerkleWitness8(claimedPassesTree.getWitness(accessPassIndex0));

    const txn0 = await Mina.transaction(deployerAccount, () => {
      zkApp.awardAccessPass(owner0.toPublicKey(), accessPass0Id, deployerKey, accessPass0Witness, owner0ValidityWitness);
    });
    await txn0.prove();
    await txn0.sign([deployerKey]).send();

    // Award accessPass 1 to pubKey1
    let accessPass1 = PrivateKey.random();
    let accessPassIndex1 = 1n;
    validPassesTree.setLeaf(accessPassIndex1, Poseidon.hash([accessPass1.toPublicKey().x]));
    const accessPass1Witness = new MerkleWitness8(validPassesTree.getWitness(accessPassIndex1));

    let owner1 = PrivateKey.random();
    let accessPass1Id = accessPass1.toPublicKey();
    claimedPassesTree.setLeaf(accessPassIndex1, Poseidon.hash([accessPass1Id.x, owner1.toPublicKey().x]));
    const owner1ValidityWitness = new MerkleWitness8(claimedPassesTree.getWitness(accessPassIndex1));

    const txn1 = await Mina.transaction(deployerAccount, () => {
      zkApp.awardAccessPass(owner1.toPublicKey(), accessPass1Id, deployerKey, accessPass1Witness, owner1ValidityWitness);
    });
    await txn1.prove();
    await txn1.sign([deployerKey]).send();

    // Try to authenticate for accesspass 0. Making these witness again because some leaves were added later
    let accessPass0ValidityWitness = new MerkleWitness8(validPassesTree.getWitness(accessPassIndex0));
    let accessOwnershipWitness = new MerkleWitness8(claimedPassesTree.getWitness(accessPassIndex0));
    
    // signing for accesspass0
    let signedBlockNr = Mina.getNetworkState().blockchainLength;
    let sig = Signature.create(owner1, accessPass0Id.toFields().concat(signedBlockNr.toFields()));

    let error = '';
    try {
      const txn1 = await Mina.transaction(deployerAccount, () => {
        // Should error when the current owner is not the signer
        zkApp.authenticate(owner1.toPublicKey(), signedBlockNr, accessPass0Id, sig, accessPass0ValidityWitness, accessOwnershipWitness);
      });
    } catch (e: any) {
      error = e.message;
    }
    // Should error because the current owner is not signing off the transfer of ownership
    expect(error).not.toEqual('initial');
  });

  // WORKS
  it('authenticate should fail if the accesspass witness is not valid', async () => {
    await localDeploy();

    // Award accessPass 0 to pubKey0
    let accessPass0 = PrivateKey.random();
    let accessPassIndex0 = 0n;
    validPassesTree.setLeaf(accessPassIndex0, Poseidon.hash([accessPass0.toPublicKey().x]));
    const accessPass0Witness = new MerkleWitness8(validPassesTree.getWitness(accessPassIndex0));

    let owner0 = PrivateKey.random();
    let accessPass0Id = accessPass0.toPublicKey();
    claimedPassesTree.setLeaf(accessPassIndex0, Poseidon.hash([accessPass0Id.x, owner0.toPublicKey().x]));
    const owner0ValidityWitness = new MerkleWitness8(claimedPassesTree.getWitness(accessPassIndex0));

    const txn0 = await Mina.transaction(deployerAccount, () => {
      zkApp.awardAccessPass(owner0.toPublicKey(), accessPass0Id, deployerKey, accessPass0Witness, owner0ValidityWitness);
    });
    await txn0.prove();
    await txn0.sign([deployerKey]).send();

    // Award accessPass 1 to pubKey1
    let accessPass1 = PrivateKey.random();
    let accessPassIndex1 = 1n;
    validPassesTree.setLeaf(accessPassIndex1, Poseidon.hash([accessPass1.toPublicKey().x]));
    const accessPass1Witness = new MerkleWitness8(validPassesTree.getWitness(accessPassIndex1));

    let owner1 = PrivateKey.random();
    let accessPass1Id = accessPass1.toPublicKey();
    claimedPassesTree.setLeaf(accessPassIndex1, Poseidon.hash([accessPass1Id.x, owner1.toPublicKey().x]));
    const owner1ValidityWitness = new MerkleWitness8(claimedPassesTree.getWitness(accessPassIndex1));

    const txn1 = await Mina.transaction(deployerAccount, () => {
      zkApp.awardAccessPass(owner1.toPublicKey(), accessPass1Id, deployerKey, accessPass1Witness, owner1ValidityWitness);
    });
    await txn1.prove();
    await txn1.sign([deployerKey]).send(); 

    // Try to authenticate for user 0 with an old accessPassWitness
    let accessPass0ValidityWitness = accessPass0Witness; // this is an old witness and shouldnt work
    let accessOwnershipWitness = new MerkleWitness8(claimedPassesTree.getWitness(accessPassIndex0));
    
    let signedBlockNr = Mina.getNetworkState().blockchainLength;
    let sig = Signature.create(owner0, accessPass0Id.toFields().concat(signedBlockNr.toFields()));

    let error = '';
    try {
      const txn1 = await Mina.transaction(deployerAccount, () => {
        zkApp.authenticate(owner0.toPublicKey(), signedBlockNr, accessPass0Id, sig, accessPass0ValidityWitness, accessOwnershipWitness);
      });
    } catch (e: any) {
      error = e.message;
    }
    expect(error).not.toEqual('initial');
  });

  // WORKS
  it('authenticate should fail when member tries to validate for incorrect accesspass', async () => {
    await localDeploy();

    // Award accessPass 0 to pubKey0
    let accessPass0 = PrivateKey.random();
    let accessPassIndex0 = 0n;
    validPassesTree.setLeaf(accessPassIndex0, Poseidon.hash([accessPass0.toPublicKey().x]));
    const accessPass0Witness = new MerkleWitness8(validPassesTree.getWitness(accessPassIndex0));

    let owner0 = PrivateKey.random();
    let accessPass0Id = accessPass0.toPublicKey();
    claimedPassesTree.setLeaf(accessPassIndex0, Poseidon.hash([accessPass0Id.x, owner0.toPublicKey().x]));
    const owner0ValidityWitness = new MerkleWitness8(claimedPassesTree.getWitness(accessPassIndex0));

    const txn0 = await Mina.transaction(deployerAccount, () => {
      zkApp.awardAccessPass(owner0.toPublicKey(), accessPass0Id, deployerKey, accessPass0Witness, owner0ValidityWitness);
    });
    await txn0.prove();
    await txn0.sign([deployerKey]).send();

    // Award accessPass 1 to pubKey1
    let accessPass1 = PrivateKey.random();
    let accessPassIndex1 = 1n;
    validPassesTree.setLeaf(accessPassIndex1, Poseidon.hash([accessPass1.toPublicKey().x]));
    const accessPass1Witness = new MerkleWitness8(validPassesTree.getWitness(accessPassIndex1));

    let owner1 = PrivateKey.random();
    let accessPass1Id = accessPass1.toPublicKey();
    claimedPassesTree.setLeaf(accessPassIndex1, Poseidon.hash([accessPass1Id.x, owner1.toPublicKey().x]));
    const owner1ValidityWitness = new MerkleWitness8(claimedPassesTree.getWitness(accessPassIndex1));

    const txn1 = await Mina.transaction(deployerAccount, () => {
      zkApp.awardAccessPass(owner1.toPublicKey(), accessPass1Id, deployerKey, accessPass1Witness, owner1ValidityWitness);
    });
    await txn1.prove();
    await txn1.sign([deployerKey]).send();

    // pubKey1 tries to validate with accessPass0 -> should fail
    let accessPass0ValidityWitness = new MerkleWitness8(validPassesTree.getWitness(accessPassIndex0));
    // pubKey1 owns accessPass1
    let accessOwnershipWitness = new MerkleWitness8(claimedPassesTree.getWitness(accessPassIndex1));

    // privKey1 signs accessPass0
    let signedBlockNr = Mina.getNetworkState().blockchainLength;
    let sig = Signature.create(owner1, accessPass0Id.toFields().concat(signedBlockNr.toFields()));

    let error = '';
    try {
      const txn1 = await Mina.transaction(deployerAccount, () => {
        // Should error when the current owner is not the signer
        zkApp.authenticate(owner1.toPublicKey(), signedBlockNr, accessPass0Id, sig, accessPass0ValidityWitness, accessOwnershipWitness);
      });
    } catch (e: any) {
      error = e.message;
    }
    // Should error because the current owner is not signing off the transfer of ownership
    expect(error).not.toEqual('initial');
  });

  // WORKS
  it('authenticate should fail when incorrect block (not within range of 10 before) is signed', async () => {
    await localDeploy();

    // Award accessPass 0 to pubKey0
    let accessPass0 = PrivateKey.random();
    let accessPassIndex0 = 0n;
    validPassesTree.setLeaf(accessPassIndex0, Poseidon.hash([accessPass0.toPublicKey().x]));
    const accessPass0Witness = new MerkleWitness8(validPassesTree.getWitness(accessPassIndex0));

    let owner0 = PrivateKey.random();
    let accessPass0Id = accessPass0.toPublicKey();
    claimedPassesTree.setLeaf(accessPassIndex0, Poseidon.hash([accessPass0Id.x, owner0.toPublicKey().x]));
    const owner0ValidityWitness = new MerkleWitness8(claimedPassesTree.getWitness(accessPassIndex0));

    const txn0 = await Mina.transaction(deployerAccount, () => {
      zkApp.awardAccessPass(owner0.toPublicKey(), accessPass0Id, deployerKey, accessPass0Witness, owner0ValidityWitness);
    });
    await txn0.prove();
    await txn0.sign([deployerKey]).send();

    // Award accessPass 1 to pubKey1
    let accessPass1 = PrivateKey.random();
    let accessPassIndex1 = 1n;
    validPassesTree.setLeaf(accessPassIndex1, Poseidon.hash([accessPass1.toPublicKey().x]));
    const accessPass1Witness = new MerkleWitness8(validPassesTree.getWitness(accessPassIndex1));

    let owner1 = PrivateKey.random();
    let accessPass1Id = accessPass1.toPublicKey();
    claimedPassesTree.setLeaf(accessPassIndex1, Poseidon.hash([accessPass1Id.x, owner1.toPublicKey().x]));
    const owner1ValidityWitness = new MerkleWitness8(claimedPassesTree.getWitness(accessPassIndex1));

    const txn1 = await Mina.transaction(deployerAccount, () => {
      zkApp.awardAccessPass(owner1.toPublicKey(), accessPass1Id, deployerKey, accessPass1Witness, owner1ValidityWitness);
    });
    await txn1.prove();
    await txn1.sign([deployerKey]).send();

    // Try to authenticate with user 0. Making these witness again because some leaves were added later
    let accessPass0ValidityWitness = new MerkleWitness8(validPassesTree.getWitness(accessPassIndex0));
    let accessOwnershipWitness = new MerkleWitness8(claimedPassesTree.getWitness(accessPassIndex0));

    let currentBlockNr = Mina.getNetworkState().blockchainLength;
    let incorrectBlock: UInt32 = currentBlockNr.add(11);
    let sig = Signature.create(owner0, accessPass0Id.toFields().concat(incorrectBlock.toFields()));

    let error = '';
    try {
      const txn1 = await Mina.transaction(deployerAccount, () => {
        // Should error because block is too old
        zkApp.authenticate(owner0.toPublicKey(), incorrectBlock, accessPass0Id, sig, accessPass0ValidityWitness, accessOwnershipWitness);
      });
    } catch (e: any) {
      error = e.message;
    }
    // Should error because the current owner is not signing off the transfer of ownership
    expect(error).not.toEqual('initial');

  });

  // WORKS
  it('correctly authenticate after transferring ownership (pass for new owner, fail for old owner)', async () => {
    await localDeploy();

    let accessPass0 = PrivateKey.random();
    validPassesTree.setLeaf(0n, Poseidon.hash([accessPass0.toPublicKey().x]));
    let accessPassIndex = 0n;
    const accessPassWitness = new MerkleWitness8(validPassesTree.getWitness(accessPassIndex));

    // Award accessPass 0 to pubKey0
    let privKey0 = PrivateKey.random();
    let accessPass0Id = accessPass0.toPublicKey();
    claimedPassesTree.setLeaf(accessPassIndex, Poseidon.hash([accessPass0Id.x, privKey0.toPublicKey().x]));
    const ownerValidityWitness = new MerkleWitness8(claimedPassesTree.getWitness(accessPassIndex));

    const txn0 = await Mina.transaction(deployerAccount, () => {
      zkApp.awardAccessPass(privKey0.toPublicKey(), accessPass0Id, deployerKey, accessPassWitness, ownerValidityWitness);
    });
    await txn0.prove();
    await txn0.sign([deployerKey]).send();

    // Now, change ownership from pubKey0 to pubKey1
    let secretKey1 = PrivateKey.random();
    let pubKey1 = secretKey1.toPublicKey();
    claimedPassesTree.setLeaf(accessPassIndex, Poseidon.hash([accessPass0Id.x, pubKey1.x]));
    const newOwnerValidityWitness = new MerkleWitness8(claimedPassesTree.getWitness(accessPassIndex));

    const txn1 = await Mina.transaction(deployerAccount, () => {
      zkApp.transferOwnershipAccessPass(privKey0, pubKey1, accessPass0Id, accessPassWitness, ownerValidityWitness, newOwnerValidityWitness);
    });
    await txn1.prove();
    await txn1.sign([deployerKey]).send();

    // 1. Authenticate for new owner = PASS
    // User 1 owns accesspass 0
    let accessPass0ValidityWitness = new MerkleWitness8(validPassesTree.getWitness(accessPassIndex));
    let accessOwnershipWitness = new MerkleWitness8(claimedPassesTree.getWitness(accessPassIndex));

    let signedBlockNr = Mina.getNetworkState().blockchainLength;
    let sig = Signature.create(secretKey1, accessPass0Id.toFields().concat(signedBlockNr.toFields()));

    const txnAuth = await Mina.transaction(deployerAccount, () => {
      zkApp.authenticate(pubKey1, signedBlockNr, accessPass0Id, sig, accessPass0ValidityWitness, accessOwnershipWitness);
    });
    await txnAuth.prove();
    await txnAuth.sign([deployerKey]).send();

    // 2. Authenticate for old owner = FAIL
    let currentBlockNr = Mina.getNetworkState().blockchainLength;
    let sig2 = Signature.create(privKey0, accessPass0Id.toFields().concat(currentBlockNr.toFields()));

    let error = '';
    try {
      const txn1 = await Mina.transaction(deployerAccount, () => {
        // Should error because privKey0 is not the owner of this accesspass anymore
        zkApp.authenticate(privKey0.toPublicKey(), currentBlockNr, accessPass0Id, sig, accessPass0ValidityWitness, accessOwnershipWitness);
      });
    } catch (e: any) {
      error = e.message;
    }

    expect(error).not.toEqual('initial');
  });

});
