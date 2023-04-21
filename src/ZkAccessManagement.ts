import { Field, SmartContract, state, State, method, Poseidon, PublicKey, MerkleWitness, PrivateKey, Signature, UInt32 } from 'snarkyjs';

export class MerkleWitness8 extends MerkleWitness(8) {}

/**
 * Private authentication for a digital gathering based on ownership of accesspasses. 
 * 
 * This contract uses an authority that can awards AccessPasses.
 * Someone who owns an AccessPass can prove this ownership and thus authenticate.
 * An accesspass can be transferred to a new owner by the current owner. 
 */
export class ZkAccessManagement extends SmartContract {
  // The authority for this AccessManagement that can awards AccessPasses
  @state(PublicKey) authority = State<PublicKey>();

  // All 256 valid accessPasses are stored in a MerkleTree
  @state(Field) validPassesRoot = State<Field>();
  @state(Field) validPassesNextIndex = State<Field>();

  // This Merkle Tree registers who (pubkey) owns what AccessPass
  // Leaves consist of a hash of those 2 pubkeys (owner pubkey + AccessPass pubkey)
  @state(Field) claimedPassesRoot = State<Field>();

  /**
   * Set the authority and other initial values.
   * This is called by the authority. 
   * 
   * Actions: 
   * - authority is updated
   * - validPassesRoot is updated
   * - claimedPassesRoot is updated
   * - validPassesNextIndex is updated
   * 
   * @param authority 
   * @param validPassesInitRoot 
   * @param claimedPassesInitRoot 
   */
  @method initState(authority: PrivateKey, validPassesInitRoot: Field, claimedPassesInitRoot: Field) {
    this.authority.set(authority.toPublicKey());
    this.validPassesRoot.set(validPassesInitRoot);
    this.claimedPassesRoot.set(claimedPassesInitRoot);
    this.validPassesNextIndex.set(Field(0));
  }

  /**
   * This is called by the authority.
   * Accesspass is issued by authority to the pubKey.
   * 
   * Checks: 
   * 1. authority equals this.authority
   * 2. claimedAccessPassWitness index and accessPassValidityWitness index are the same
   * 
   * Actions: 
   * - validPassesRoot is updated: a new leaf is added at index validPassesNextIndex that contains the new accessPass
   * - validPassesNextIndex is updated
   * - claimedPassesRoot is updated: a new leaf is added at validPassesNextIndex that contains a hash of the accesspass and owner
   * 
   * @param pubKey 
   * @param accessPass 
   * @param authoritySecret 
   * @param accessPassWitness 
   * @param claimedAccessPassWitness 
   */
  @method awardAccessPass(pubKey: PublicKey, accessPass: PublicKey, authoritySecret: PrivateKey, accessPassWitness: MerkleWitness8, claimedAccessPassWitness: MerkleWitness8) {
    // 1. Check: authority equals this.authority
    const storedAuthorityPublicKey = this.authority.get();
    this.authority.assertEquals(storedAuthorityPublicKey);
    storedAuthorityPublicKey.assertEquals(authoritySecret.toPublicKey());

    // 2. Add a new leaf to the validPasses tree at index validPassesNextIndex that contains the accessPass
    const currentValidPassesRoot = this.validPassesRoot.get();
    this.validPassesRoot.assertEquals(currentValidPassesRoot);

    const nextIndex = this.validPassesNextIndex.get();
    this.validPassesNextIndex.assertEquals(nextIndex);
    this.validPassesNextIndex.assertEquals(accessPassWitness.calculateIndex());

    // 3. Update validPassesRoot and validPassesNextIndex
    const newRootValidPasses = accessPassWitness.calculateRoot(Poseidon.hash([accessPass.x]));
    this.validPassesRoot.set(newRootValidPasses);
    this.validPassesNextIndex.set(nextIndex.add(Field(1)));  

    // 4. Check: claimedAccessPassWitness index and accessPassValidityWitness index are the same: we store the owner of the access pass in the same spot
    // For now, we assume that the caller knows the index of the accesspass
    (accessPassWitness.calculateIndex()).assertEquals(claimedAccessPassWitness.calculateIndex());

    // 5. Update claimedPassesRoot - this stores ownership
    const newRoot = calculateRootNewOwner(claimedAccessPassWitness, accessPass, pubKey);
    this.claimedPassesRoot.set(newRoot);
  }

  /**
   * This is called by current owner of accesspass. 
   * Accesspass ownership is transferred to new owner.
   * 
   * Checks: 
   * 1. accessPass is valid
   * 2. currentOwnerPubKey is indeed the owner of that accessPass
   * 3. new owner is for the same tree index as the accessPass
   * 
   * Actions:
   * - claimedPassesRoot is updated
   * 
   * @param currentOwnerSecret 
   * @param newOwner 
   * @param accessPass 
   * @param accessPassValidityWitness 
   * @param currentOwnerValidityWitness 
   * @param newOwnerWitness 
   */
  @method transferOwnershipAccessPass(currentOwnerSecret: PrivateKey, newOwner: PublicKey, accessPass: PublicKey, accessPassValidityWitness: MerkleWitness8, currentOwnerValidityWitness: MerkleWitness8, newOwnerWitness: MerkleWitness8) {
    // 1. Check: accessPassValidityWitness proves that the accessPass is stored in accessPass tree => AccessPass is valid
    this.validPassesRoot.assertEquals(accessPassValidityWitness.calculateRoot(Poseidon.hash([accessPass.x])));

    // 2. Check: currentOwnerValidityWitness proves that currentOwnerPubKey is indeed the owner of that AccessPass
    // Check equal index and check equal roots
    (accessPassValidityWitness.calculateIndex()).assertEquals(currentOwnerValidityWitness.calculateIndex());
    this.claimedPassesRoot.assertEquals(currentOwnerValidityWitness.calculateRoot(Poseidon.hash([accessPass.x, currentOwnerSecret.toPublicKey().x])));

    // 3. Check the updated owner is for the same index
    (newOwnerWitness.calculateIndex()).assertEquals(currentOwnerValidityWitness.calculateIndex());

    // 4. Update claimedPassesRoot
    const newRoot = calculateRootNewOwner(newOwnerWitness, accessPass, newOwner);
    this.claimedPassesRoot.set(newRoot);
  }

  /**
   * This is called by authenticator (= owner of a valid accesspass)
   * Correctly authenticates if the authenticator proves ownership of a valid accessPass.
   * Replay attack prevention by including a blocknr which cannot be more than 10 blocks behind. 
   * 
   * Checks:
   * 1. accessPass is valid
   * 2. signedBlockNr is within 10 blocks of now
   * 3. signature was made by authenticator (owner of accessPass)
   * 4. accessPass is owned by authenticator
   * 
   * @param authenticator the one who is trying to authenticate
   * @param signedBlockNr include blocknr to prevent replay attack
   * @param accessPass authenticator is owner of this accesspass
   * @param signature on the accesspass and blocknr 
   * @param accessPassValidityWitness proves the accesspass is a valid entry for the gathering
   * @param accessOwnershipWitness  proves the authenticator is the current owner of the accesspass
   */
  @method authenticate(authenticator: PublicKey, signedBlockNr: UInt32, accessPass: PublicKey, signature: Signature, accessPassValidityWitness: MerkleWitness8, accessOwnershipWitness: MerkleWitness8) {
    // 1. Check: accessPassValidityWitness proves that the accessPass is stored in accessPass tree => AccessPass is valid
    this.validPassesRoot.assertEquals(accessPassValidityWitness.calculateRoot(Poseidon.hash([accessPass.x])));

    // 2. Check: signedBlockNr is within 10 blocks of now (prevents replay attack)
    let currentBlockchainLength = this.network.blockchainLength.get();
    this.network.blockchainLength.assertEquals(currentBlockchainLength);
    currentBlockchainLength.lessThanOrEqual(signedBlockNr.add(10)).assertTrue();

    // 3. Check: owner of accessPass signed (accesspass, signedBlockNr)
    signature.verify(authenticator, accessPass.toFields().concat(signedBlockNr.toFields())).assertTrue();

    // 4. Check: accessOwnershipWitness proves that pubKey is indeed the owner of that AccessPass
    this.claimedPassesRoot.assertEquals(accessOwnershipWitness.calculateRoot(Poseidon.hash([accessPass.x, authenticator.x])));
  }
}

/**
 * returns the newly calculated root for leaf Hash(accesspass, owner)
 * 
 * @param ownerWitness 
 * @param accessPass 
 * @param owner 
 * @returns 
 */
function calculateRootNewOwner(ownerWitness: MerkleWitness8, accessPass: PublicKey, owner: PublicKey): Field {
  return ownerWitness.calculateRoot(Poseidon.hash([accessPass.x, owner.x]));
}

