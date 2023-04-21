# ZKP / Web3 Hackathon

Write-up about this project. See the `README.md` for information on how to run this codebase. 

## 1 An overall description of your submission
This is a zkApp that handles anonymous authentication for members of a digital community. It can be called a "ZK Access Management System".

You can get access to a digital space based on an accesspass, but nobody needs to know who you are. 

### Functionality
This codebase implements the backend, issuing up to 256 accesspasses that allow members to correctly authenticate. 

More specifically, the backend contains the following functionality:
- Award AccessPass (only by authority)
- Transfer ownership of AccessPass
- Authenticate anonymously

## 2 The technology used in your implementation
For this project [MINA](https://docs.minaprotocol.com/) and [SnarkyJS](https://docs.minaprotocol.com/zkapps/snarkyjs-reference) was used. 

## 3 A description of how you approached your problem
*Preparation*: To create this project I followed a couple of tutorials provided by Mina. Also, I assisted the special meeting that was held for this track to ask some additional questions.

*Initial idea*: The initial idea was to update the earlier created Shamir Sharing codebase and then try a different (partially) homomorphic implementation. With the time constraint, I didn't manage to get this to work. 

*Zk Access Management System*: the code was created roughly in 4 steps:
1. Write down functionality for the zk access system:
  - 3 functions with the checks that are needed
  - storage system design of 2 MerkleTrees for the accesspasses and the ownership
2. Implement a first function and make a passing and failing test work.
3. Implement the 1st version of all functionality.
4. After a break, review the code again and make an update version + added comments and documentation.

A major challenge was the time it took to run tests. For the final version, running all tests took 2865.467s. 