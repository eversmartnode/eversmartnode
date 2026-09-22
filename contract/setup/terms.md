# EverAdmin EV Signer Setup — Security Notes

This page exists only to prepare credentials for EverAdmin Control Plane and EV Signer.

It can generate or handle two sensitive credentials:

- an Everstoring/HotPocket Ed25519 admin private key;
- an OTP secret shared between the EverAdmin user record and EV Signer.

The **admin public key** is the identity EverAdmin stores for an Everstoring/signer user. The **admin private key** must stay private and belongs in EV Signer or another secure backup; it should not be submitted to EverAdmin. The **OTP secret** is intentionally shared with the corresponding EverAdmin user record because EverAdmin needs it to verify signer authorization envelopes.

The page does not require or generate an XRPL/Xahau wallet seed, classic R-address, trustline, or wallet encryption output. Those are unrelated to EverAdmin login authentication.

All generation performed by this page happens in the browser. Treat displayed secrets and QR codes as sensitive. Avoid shared or untrusted devices, browser extensions you do not trust, screenshots, screen sharing, clipboard history, or any environment where secrets could be captured.

Keep a secure backup before closing the page. Loss of the admin private key can prevent use of the matching signer identity.
