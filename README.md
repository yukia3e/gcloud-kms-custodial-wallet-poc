# GCloud KMS Custodial Wallet PoC

This repository contains a Proof of Concept (PoC) implementation of a custodial wallet service for users, using Google Cloud Key Management Service (KMS) and written in Golang. This PoC is not intended for production use.

## Disclaimer

**This is a Proof of Concept and is not intended for production use.** It is provided "as-is" without any warranties or guarantees.

## Project Structure

The project is designed with a layered architecture, implementing only the domain and infrastructure layers. Although the use case layer is not fully implemented, the functionality is directly tested through `cmd/test/main.go` for simplicity.

## Features

1. **Key Management with Google Cloud KMS**:

   - Creation of a key version for each user in a pre-created Keyring.
   - Derivation and retrieval of wallet addresses using these keys.
   - ECDSA signature creation and SendTransaction using these keys.

2. **Polygon Gas Information Retrieval**:
   - Includes functionality to retrieve gas price information from Polygon Gas Station for decision-making on gas values.

## Getting Started

1. Create a Google Cloud project and enable the KMS API.
2. Create Service Account and download the JSON key file as `.gcloud/credentials.json`.
3. Pre-created Keyring in Google Cloud KMS.
4. Set environment variables to .env file:
   ```shell
   APP_ENV=local
   GCP_PROJECT_ID=your-project-id
   KEY_RING_ID=your-keyring
   FIREBASE_CREDENTIAL_FILE_PATH=.gcloud/credentials.json
   ```
5. Create a user key by `CreateCryptoKey`
