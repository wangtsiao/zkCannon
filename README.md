<p align="center">
<img src="https://github.com/wangtsiao/zkCannon/blob/main/zkmips-logo.png" height="100" />
</p>

> WARNING: This software is still experimental, we do not recommend it for production use (see Security section).

zkMIPS is a zero-knowledge verfiable general computing platform based on [halo2](https://eprint.iacr.org/2019/1021.pdf) and the [MIPS](https://www.wikiwand.com/en/MIPS_architecture) microarchitecture.

A [non-interactive zero-knowledge proof](https://en.wikipedia.org/wiki/Non-interactive_zero-knowledge_proof) is a method where one person, called the prover, can convince another person, known as the verifier, that a certain statement is true without revealing all the specific details. In the context of zkMIPS, the prover can demonstrate that they have correctly executed a particular piece of code known to both parties. The prover only needs to reveal the output of the code to the verifier, without disclosing any input values or any intermediate states during the execution.

The code runs in a special virtual machine, called a *zkVM*. The zkMIPS zkVM emulates a small [MIPS](https://en.wikipedia.org/wiki/RISC-V) computer, allowing it to run arbitrary code in any language, so long as a compiler toolchain exists that targets MIPS.

## Protocol overview and terminology





## Security





## Getting Started





## License

This project is licensed under the Apache2 license. See [LICENSE](https://github.com/wangtsiao/zkCannon/blob/main/LICENSE).
