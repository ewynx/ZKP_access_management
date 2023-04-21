# Mina zkApp: ZK Access Management

Anonymously authenticate to a digital space, based on ownership of an accessPass. 

For example, the accesspasses can be a limited collection of NFTs which give you access to a certain community. 

You can get in to the community with your accesspass, but within the community you can go around anonymously, because of the private authentication. 

## Functionality

This Access Management System contains the following functionality:
- Award AccessPass (only by authority)
- Transfer ownership of AccessPass
- Authenticate anonymously

Noe: there's a limited amount of accessPasses (256).

## State
"While the state of a zkApp is public, method parameters are private." from the [Mina docs](https://docs.minaprotocol.com/zkapps/how-to-write-a-zkapp#public-and-private-inputs).

In the state, the accessPasses and their owners will be stored in 2 MerkleTrees.

An accessPass is currently represented as a public key. Ownership is stored as hash(accessPass, ownerPubkey). 


## STATUS OF CODEBASE

All tests pass. 

### Testinstructions


```sh
npm run build
npm run test
```


## License

[Apache-2.0](LICENSE)
