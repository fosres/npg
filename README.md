## Third-Place Winner of HackWesTXII
## Youtube Link
Demo 1:https://www.youtube.com/watch?v=9CnKlbXzxTs&feature=youtu.be

Demo 2:https://www.youtube.com/watch?v=G5d4EPnKlhE&feature=youtu.be
## Inspiration
The inspiration was GNUPG. GNUPG is an implementation of Pretty Good Privacy, a software encryption suite designed for secure communication. But there were two problems with GNUPG: GNUPG's ciphers did not defend against timing-side channel attacks and they were slower. Moreover, the ciphers that were part of the libsodium programming library did. It is my intention to advance NPG to securely communicate with people through email. The basic idea is that whoever sends us email must be properly encrypted and digitally signed by the proper keys. Otherwise, the server will instantaneously destroy the email. Moreover, it is my intention to upgrade a previous hackathon project, prm (https://github.com/fosres/prm), with NPG so files are even better protected against security compromises. By securely encrypting each and every file in a directory with a randomized password as described below, crackers will have an even more difficult time finding the information they need. 
## What it does
It is fully capable of encrypting a file with a random password of any length. This random password will itself be encrypted by the public key of the intended recipient. This is done to ensure only the true recipient can decrypt the password and thus only the true recipient can read the raw, unencrypted email message. Finally, the encrypted email message itself is hashed with the SHA-512 algorithm and this hash is itself encrypted with the sender's private subkey. This special encrypted hash is known as the digital signature of the email message. In the recipient can detach the digital signature, decrypt the hash with the public key of the sender, and then compare the SHA512-hash that they have received from the sender and compare it with the hash they themselves compute with SHA-512. If the hashes match, then there is reliable assurance that the encrypted email message indeed came from the proposed sender. 
## How I built it
I used the libsodium (https://download.libsodium.org/doc/) programming library to build this minimum viable prototype of npg.
## Challenges I ran into
Verification of signatures for messages was surprisingly difficult. The computer continuously reported failed verification of signatures of messages until I moved the location of the variables that functions needed to to verify signatures.
## Accomplishments that I'm proud of
I even got the encrypted, digitally signed file to be converted into radix64 encoding. This ensures that binary files can be transported to any machine as long as they support ASCII.
## What I learned
I learned plenty on the logic behind confidentiality, integrity, the difference between the two, the flexibility in using asymmetric ciphers for both purposes, and 
## What's next for npg
NPG will be especially useful for securely encrypting metadata. When metadata is encrypted, all the information that is listed on a file will look like gibberish in the command terminal no matter what tool is used to gather information on the file. This will make the cracker's life ever more difficult in first finding,let alone cracking a file that contains valuable information for them. In the future, npg users will be capable of sending single-bodied email messages that can be decrypted and verified by other npg users provided that they have the right public key and/or secret keys.
I actually intend NPG to serve as a substitute for GNUPG since it offers ciphers that are both safer and faster than GPG's own. Not only is it supposed to assist in secure backups. But it is flexible enough to be used for digitally signing one's work (e.g. source code). It is also the foundation for a kernel patch I wish to make to eCryptfs, Canonical's kernel project to encrypt filesystems. I wish to use NPG to perform the same type of encryption you can perform on a file with all files throughout the user's filesystem to protect them from malware that have gained online access to a user's machine.

