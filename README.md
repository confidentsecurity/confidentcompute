# Confident-Compute

Confident-Compute contains the necessary components for CONFSEC's ComputeNode component of the OpenPCC standard. To read more about OpenPCC, please visit https://github.com/openpcc/openpcc

## Components

The Confident Compute repo consists of the following top level directories:

Go code for individual compute "service" binaries, including:
- `compute_boot`: The main entrypoint for the compute node. This service is responsible for attesting to the TPM, GPU, and other hardware components, in preparation for `router_com` to start.
- `router_com`: The service that receives requests from the router and forwards them to the `compute_worker` service (which is spawned as a new process for each request).
- `compute_worker`: The service that actually performs the computation. This service is responsible for decrypting the request, sending it to the LLM, and encrypting the response.

Source code for building the compute node image:
- `compute-images`: Packer scripts for building the compute node image in its entirety. This includes scripts for building several "base" images, as well as scripts for building the final build image artifact on multiple clouds.

See [compute-images/README.md](./compute-images/README.md) for more information to that end.
