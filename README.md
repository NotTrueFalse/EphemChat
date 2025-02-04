# EphemChat

This repository marks the initial phase of a larger project. I'm sharing it here to establish authorship in case the idea is shared or used by others before I can fully develop it. Consider this a way to say, "I'm the original author of this project."

## Overview

EphemChat is a secure communication platform designed to ensure privacy and security between two users. The core idea is to allow users to share a small **address|seed pair** to establish a connection. The goal is to make the conversation resistant to common attacks such as replay attacks, brute force attempts, and sniffing techniques—even if the server is compromised.

### Key Features
- **Client-Side Security**: The server is intentionally kept simple, while the client handles all the complex security measures. This ensures that even if the server is compromised, user conversations remain secure.
- **One-Time Verifier (OTV)**: A unique, cryptographically secure verifier is used to confirm that you're communicating with the intended contact. This adds an extra layer of security to prevent impersonation.

## How It Works

1. **Address|Seed Pair**: Users exchange a small, unique pair to initiate a connection.
2. **Secure Communication**: All messages are encrypted using AES, wrapped with a One-Time Verifier (OTV) to ensure authenticity and integrity.
3. **Server Resilience**: The server is designed to be minimalistic, so even if it is compromised, the security of the conversation relies entirely on the client-side implementation.

## One-Time Verifier (OTV)

The OTV is a cryptographically secure random value generated to verify the identity of the contact you're communicating with. It ensures that you're talking to the right person and not an imposter. (Note: The randomness of the OTV generator is currently under review for potential improvements.)

## Current Status

⚠️ **Under Construction**: The project is still in development. A bug in the random generator is currently being investigated. Once resolved, a stable version will be released.

## Feedback and Contributions

Found a bug? Have suggestions for improvements? Think RSA would be a better fit than the current seed-based encryption? Feel free to open an issue and share your thoughts! I'm open to constructive feedback and ideas to make EphemChat even more secure and efficient.

---

### Why This Matters

In an era where privacy is increasingly important, EphemChat aims to provide a lightweight yet secure communication solution. By focusing on client-side security, the project ensures that user data remains protected, even in the face of server compromises.