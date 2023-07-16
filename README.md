<p align="center">
<img src="https://github.com/wangtsiao/zkCannon/blob/main/zkmips-logo.png" height="100" />
</p>

> WARNING: This software is still experimental, we do not recommend it for production use (see Security section).

zkMIPS is a zero-knowledge verfiable general computing platform based on [halo2](https://eprint.iacr.org/2019/1021.pdf) 
and the [MIPS](https://www.wikiwand.com/en/MIPS_architecture) micro-architecture.

A [non-interactive zero-knowledge proof](https://en.wikipedia.org/wiki/Non-interactive_zero-knowledge_proof) is a 
method where one person, called the prover, can convince another person, known as the verifier, that a certain 
statement is true without revealing all the specific details. In the context of zkMIPS, the prover can demonstrate 
that they have correctly executed a particular piece of code known to both parties. The prover only needs to reveal 
the output of the code to the verifier, without disclosing any input values or any intermediate states during the 
execution.

The code runs in a special virtual machine, called a *zkVM*. The zkMIPS zkVM emulates a small
[MIPS](https://en.wikipedia.org/wiki/RISC-V) computer, allowing it to run arbitrary code in any language, so long as 
a compiler toolchain exists that targets MIPS.

## Protocol overview and terminology
The code to be proven must be compiled from its implementation language into the MIPS ELF file.
Next zkMIPS's emulator will generate a special type of cryptographic hash of the ELF file, in particular, we use
[Sinsemilla](https://zips.z.cash/protocol/protocol.pdf#concretesinsemillahash) hash here, and the hash result is 
required for verification. This ensures that the prover is indeed running the same program it committed.

Next, the host program runs and proves the method inside the zkVM. The logical MIPS machine running inside the zkVM 
is called the guest and the prover running the zkVM is called the host. The guest and the host can communicate with
each other during the execution of the method, but the host cannot modify the execution of the guest in any way, or 
the proof being generated will be invalid. During execution, the guest code can write to a special append-only log 
called the journal that represents the official output of the computation.

Presuming the method terminated correctly, a receipt is produced, which provides the proof of correct execution. This 
receipt consists of 2 parts: the journal written during execution and a blob of opaque cryptographic data called the seal.

The verifier can then verify the receipt and examine the log. If any tampering was done to the journal or the seal, the 
receipt will fail to verify. Additionally, it is cryptographically infeasible to generate a valid receipt unless the 
output of the journal is the exactly correct output for some valid execution of the method whose image ID matches the 
receipt. In summary, the receipt acts as a zero knowledge proof of correct execution.

Because the protocol is zero knowledge, the verifier cannot infer anything about the details of the execution or any 
data passed between the host and the guest (aside from what is implied by the data written to the journal and the 
correct execution of the code).

## Security

This code is based on the well studied Halo2 protocol, a zkSNARK protocol, which has been proven secure under the 
discrete logarithm problem. Our implementation uses the ethereum foundation's 
[halo2 community edition version](https://github.com/privacy-scaling-explorations/halo2), which use BN256 curve and 
[KZG](https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf) polynomial commitment.

Please be aware that this code is still undergoing significant development and has not yet undergone a formal audit. 
As a result, there might be bugs present in the circuit implementation, the arithmetic circuit used for the MIPS zkVM
instantiation, or any other part of the code's implementation. These bugs could potentially affect the security of 
receipts, lead to information leaks, or cause other issues. So, it's essential to exercise caution and be mindful of 
potential risks.


## Getting Started




## License

This project is licensed under the Apache2 license. See [LICENSE](https://github.com/wangtsiao/zkCannon/blob/main/LICENSE).
