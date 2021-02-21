# TODO tasks for gerbil-crypto

## Memory Hardening

- Make sure private keys never stay in RAM longer than necessary.

- Overwrite I/O buffers with random salt after they may have contained sensitive data.

- Move key management to its own separate process.

## Support Hardware Key Management

- Use some hardware key management system so a master key is used to encrypt the keys
  (using a fast symmetric cypher plus salt), and those keys are kept encrypted,
  and only decrypted temporarily in buffer that gets overwritten with random noise
  as soon as they are not used anymore.

- This reduces the odds of a breach causing keys to leak
  (SPECTER attack, RAM extraction attack, etc.). Same for any required clear-text password
  or security token, and for keys for other cyphers -- thus many shared functions and macros.
