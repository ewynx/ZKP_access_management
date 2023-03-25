import { Field, SmartContract, state, State, method, Poseidon, PublicKey, MerkleWitness, PrivateKey } from 'snarkyjs';

export class MerkleWitness8 extends MerkleWitness(8) {}

/**
 * 
 */
export class SPSAccessManagement extends SmartContract {
  // SPS = Secret Pet Society
  @state(PublicKey) spsPublicKey = State<PublicKey>();

  // All 256 valid accessPasses are stored in a MerkleTree
  @state(Field) validPassesRoot = State<Field>();
  @state(Field) validPassesNextIndex = State<Field>();

  // This Merkle Tree registers who (pubkey) owns what AccessPass
  // Leaves consist of a hash of those 2 pubkeys (owner pubkey + AccessPass pubkey)
  @state(Field) claimedPassesRoot = State<Field>();

  @method initState(spsPublicKey: PublicKey, validPassesInitRoot: Field, claimedPassesInitRoot: Field) {
    this.spsPublicKey.set(spsPublicKey);
    this.validPassesRoot.set(validPassesInitRoot);
    this.claimedPassesRoot.set(claimedPassesInitRoot);
    this.validPassesNextIndex.set(Field(0));
  }

  // The SPC issues an accessPass to pubKey
  // Aftwerwards: 
  // - pubKey is recognized as the owner of accesspass
  // - validPassesRoot is updated to contain the new accessPass
  // - claimedPassesRoot is updated to contain a new leaf pubkey + accesspass in the index of the accesspass
  @method awardAccessPass(pubKey: PublicKey, accessPass: PublicKey, authoritySecret: PrivateKey, accessPassWitness: MerkleWitness8, claimedAccessPassWitness: MerkleWitness8) {
    // 1. Check: authority equals this.spsPublicKey
    const storedSpsPublicKey = this.spsPublicKey.get();
    this.spsPublicKey.assertEquals(storedSpsPublicKey);
    storedSpsPublicKey.assertEquals(authoritySecret.toPublicKey());

    // 2. Add a new leaf to the validPasses tree at index validPassesNextIndex that contains the accessPass
    const currentValidPassesRoot = this.validPassesRoot.get();
    this.validPassesRoot.assertEquals(currentValidPassesRoot);

    const nextIndex = this.validPassesNextIndex.get();
    this.validPassesNextIndex.assertEquals(nextIndex);
    this.validPassesNextIndex.assertEquals(accessPassWitness.calculateIndex());

    // 3. Update validPassesRoot and validPassesNextIndex
    const newRootValidPasses = accessPassWitness.calculateRoot(Poseidon.hash([accessPass.x]));//TODO hash this
    this.validPassesRoot.set(newRootValidPasses);
    this.validPassesNextIndex.set(nextIndex.add(Field(1)));  

    // 4. Check: claimedAccessPassWitness index and accessPassValidityWitness index are the same: we store the owner of the access pass in the same spot
    // For now, we assume that the caller knows the index of the accesspass
    (accessPassWitness.calculateIndex()).assertEquals(claimedAccessPassWitness.calculateIndex());

    // 5. Update claimedPassesRoot - this stores ownership
    const newRoot = claimedAccessPassWitness.calculateRoot(Poseidon.hash([accessPass.x, pubKey.x])); // TODO hash this
    this.claimedPassesRoot.set(newRoot);
  }

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
    // TODO get function out, so updating owner is always the same, also for award
    const newRoot = newOwnerWitness.calculateRoot(Poseidon.hash([accessPass.x, newOwner.x])); // TODO hash this
    this.claimedPassesRoot.set(newRoot);
  }

  @method authenticate(privKey: PrivateKey, accessPass: PublicKey, accessPassValidityWitness: MerkleWitness8, accessOwnershipWitness: MerkleWitness8) {
    // 1. Check: accessPassValidityWitness proves that the accessPass is stored in accessPass tree => AccessPass is valid
    this.validPassesRoot.assertEquals(accessPassValidityWitness.calculateRoot(Poseidon.hash([accessPass.x])));

    // 2. Check: accessOwnershipWitness proves that pubKey is indeed the owner of that AccessPass => authenticate = true
    this.claimedPassesRoot.assertEquals(accessOwnershipWitness.calculateRoot(Poseidon.hash([accessPass.x, privKey.toPublicKey().x])));
  }
}
