# Trusted Setups-as-a-Service

This repository contains the code for the Trusted Setups-as-a-Service (TSaaS) project. The goal of this project is to provide a service that allows users to generate and verify the parameters of a trusted setup ceremony for zero-knowledge proofs. The service is designed to be used by developers of zero-knowledge applications, who want to avoid the hassle of setting up a trusted setup ceremony themselves. The service is also designed to be used by users of zero-knowledge applications, who want to verify the parameters of a trusted setup ceremony.

The service is currently in development. The code in this repository is not yet ready for production use.

The Groth16 ceremony code here is modified from Penumbra's [Trusted Setup Ceremony](https://github.com/penumbra-zone/penumbra/blob/main/crates/crypto/proof-setup) code to support arbitrary pairing friendly elliptic curves.

The code here will also be used for future proof systems, such as Marlin and PLONK and more.