# Capsara SDK - .NET

A **capsa** is a zero-knowledge encrypted envelope for securely exchanging files and data between multiple parties. Each capsa is sealed with its own encryption key and can only be opened by the parties explicitly authorized to access it. Capsara never sees your content, your keys, or your metadata.

## Features

- **AES-256-GCM** encryption with unique keys per capsa
- **RSA-4096-OAEP** key encryption for multi-party access
- **Compression** with gzip before encryption
- **Digital signatures** using RSA-SHA256 for sender authenticity
- **Encrypted subject, body, and structured data**
- **Batch sending** with automatic chunking

## Installation

```bash
dotnet add package Capsara.SDK
```

Or via the Package Manager Console:

```powershell
Install-Package Capsara.SDK
```

## Initialize the Client

```csharp
using Capsara.SDK;

var client = new CapsaraClient("https://your-api-url.com");
```

## Authentication

Authentication requires two steps: login with your credentials, then set your private key for cryptographic operations.

### Login

```csharp
using Capsara.SDK.Models;

await client.LoginAsync(new AuthCredentials("you@example.com", "..."));
```

### Set Private Key

After logging in, set your private key for signing and decryption. Generate and register your keypair using `GenerateKeyPair()` and `AddPublicKeyAsync()`, then store the private key securely.

```csharp
// Your code to load the private key from secure storage (key vault, HSM, etc.)
var privateKey = LoadPrivateKeyFromSecureStorage();

client.SetPrivateKey(privateKey);
```

## Sending Capsas

Use the `CapsaBuilder` to create capsas with recipients and files. Always use `SendCapsasAsync()` even for a single capsa since it handles encryption and batching efficiently.

```csharp
using Capsara.SDK.Exceptions;
using Capsara.SDK.Models;

try
{
    // Create a builder for each capsa you want to send
    var builder = await client.CreateCapsaBuilderAsync();

    // Add recipients (can add multiple)
    builder.AddRecipient("party_recipient1");
    builder.AddRecipient("party_recipient2");

    // Add files from path or buffer
    builder.AddFile(FileInput.FromPath("./documents/policy.pdf"));
    builder.AddFile(FileInput.FromBuffer(
        Encoding.UTF8.GetBytes("Policy data here"),
        "policy-data.txt"
    ));

    // Add optional metadata
    builder.Subject = "Policy Documents - Q1 2025";
    builder.Body = "Please review the attached policy documents.";
    builder.Structured = new { PolicyNumber = "POL-12345", EffectiveDate = "2025-01-01" };

    // Set expiration
    builder.Expiration = DateTimeOffset.UtcNow.AddDays(90);

    // Send
    var result = await client.SendCapsasAsync(new[] { builder });
    Console.WriteLine($"Sent {result.Successful} capsa(s)");

    if (result.Failed > 0)
    {
        Console.Error.WriteLine($"{result.Failed} capsas failed to send");
    }
}
catch (CapsaraException ex)
{
    Console.Error.WriteLine($"Failed to send: {ex.Message}");
}
```

A **capsa** maps one-to-one with a *matter*, which is a unique combination of sender, recipient, client, and action. You can send multiple capsas in one call:

```csharp
var matter1 = await client.CreateCapsaBuilderAsync();
matter1.Subject = "Client 1 - New Home Policy";
matter1
    .AddRecipient("party_org_b")
    .AddFile(FileInput.FromPath("./policy.pdf"));

var matter2 = await client.CreateCapsaBuilderAsync();
matter2.Subject = "Client 1 - Auto Endorsement";
matter2.Body = "Endorsement effective 3/1. No documents required.";
matter2.AddRecipient("party_org_b");

await client.SendCapsasAsync(new[] { matter1, matter2 });
```

The SDK automatically splits large batches to stay within server limits.

## Receiving Capsas

### List Capsas

```csharp
var response = await client.ListCapsasAsync(new CapsaListFilters
{
    Status = "active",
    Limit = 50
});

Console.WriteLine($"Found {response.Capsas.Count} capsas");

foreach (var capsa in response.Capsas)
{
    Console.WriteLine($"- {capsa.Id}: {capsa.FileCount} files");
    Console.WriteLine($"  Created: {capsa.CreatedAt}");
    Console.WriteLine($"  From: {capsa.CreatorId}");
}

// Pagination
if (response.Pagination.HasMore)
{
    var nextPage = await client.ListCapsasAsync(new CapsaListFilters
    {
        After = response.Pagination.NextCursor
    });
}
```

### Get Capsa and Download Files

```csharp
var capsa = await client.GetDecryptedCapsaAsync("capsa_abc-123");

Console.WriteLine($"Subject: {capsa.Subject}");
Console.WriteLine($"Body: {capsa.Body}");
Console.WriteLine($"Structured data: {capsa.Structured}");

// Download each file
foreach (var file in capsa.Files)
{
    var result = await client.DownloadFileAsync(capsa.PackageId, file.Id);
    await File.WriteAllBytesAsync($"./downloads/{result.Filename}", result.Data);
}
```

## Delegation

Capsara supports delegation for scenarios where a system acts on behalf of a party. For example, an agency management system (AMS) might process capsas on behalf of the agencies it serves. When a capsa is sent to a delegated recipient, the delegate receives its own RSA-encrypted copy of the master key. If the recipient also has a public key registered in the system, they receive their own encrypted copy as well. Otherwise, only the delegate can decrypt on their behalf.

If you're a delegate, the flow is identical to receiving. List your capsas and check the `ActingFor` field on each one to see which party it belongs to. This lets you route the data to the correct recipient in your system.

```csharp
// Authenticate as the delegate (e.g., an AMS)
var client = new CapsaraClient("https://your-api-url.com");
await client.LoginAsync(new AuthCredentials("ams@example.com", "..."));
client.SetPrivateKey(LoadPrivateKeyFromSecureStorage());

// List capsas (includes capsas for all parties you represent)
var response = await client.ListCapsasAsync();

foreach (var summary in response.Capsas)
{
    var capsa = await client.GetDecryptedCapsaAsync(summary.Id);

    // Check who this capsa is for
    if (capsa.ActingFor != null)
    {
        Console.WriteLine($"Capsa {summary.Id} is for agency {capsa.ActingFor}");
        RouteToAgency(capsa.ActingFor, capsa);
    }

    // Download and process files
    foreach (var file in capsa.Files)
    {
        var result = await client.DownloadFileAsync(summary.Id, file.Id);
        ProcessFile(capsa.ActingFor, result.Filename, result.Data);
    }
}
```

## Encryption

Every capsa is protected by a unique AES-256-GCM symmetric key (the "master key") generated at send time. Files and metadata (subject, body, and structured data) are each encrypted with this master key using a fresh random IV, producing authenticated ciphertext that guarantees both confidentiality and tamper detection. The master key itself is then encrypted once per authorized party and any authorized delegates using their RSA-4096 public key with OAEP-SHA256 padding, so only the holder of the corresponding private key can recover it. Each file is independently hashed with SHA-256 before encryption, and these hashes along with all IVs are bound into a canonical string that the sender signs using RS256 (RSA-SHA256 in JWS format). Recipients and the server validate this signature against the sender's public key before trusting any content, ensuring both authenticity and integrity of the entire capsa. Key fingerprints are SHA-256 hashes of the public key PEM, providing a compact identifier for key verification. Files are gzip-compressed before encryption by default to reduce storage and transfer costs. All encryption, decryption, signing, and verification happen locally in the SDK. Capsara's servers only ever store ciphertext and cannot read your files, your metadata, or your keys.

## Private Key Security

Your private key is the sole point of access to every capsa encrypted for you. Capsara uses zero-knowledge encryption: your private key never leaves your environment, is never transmitted to Capsara's servers, and is never stored by Capsara. There is no recovery mechanism, no master backdoor, and no support override. If your private key is lost, every capsa encrypted for your party becomes permanently inaccessible. No one (not Capsara, not the sender, not an administrator) can recover your data without your private key.

You are fully responsible for your private key's lifecycle: generation, secure storage, and backup. Store it in a cloud key vault (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault), a hardware security module, or at minimum an encrypted secrets manager. Never store it in source code, configuration files, or logs. Back it up to a secondary secure location so that a single infrastructure failure does not result in permanent data loss.

The SDK provides a `RotateKeyAsync()` method that generates a new RSA-4096 key pair and registers the new public key with Capsara. New capsas sent to you will be encrypted with your new key. However, capsas are immutable once created and their keychain and encrypted contents never change. Existing capsas remain accessible only with the private key that was active when they were created. Keep prior private keys available for as long as you need access to capsas encrypted under them.

## API Reference

| Method | Description |
|--------|-------------|
| `CapsaraClient.GenerateKeyPair()` | Generate an RSA-4096 key pair (static) |
| `LoginAsync(credentials)` | Authenticate with email and password |
| `LogoutAsync()` | Log out and clear cached data |
| `SetPrivateKey(privateKey)` | Set the private key for signing and decryption |
| `CreateCapsaBuilderAsync()` | Create a `CapsaBuilder` pre-loaded with server limits |
| `SendCapsasAsync(builders)` | Encrypt and send one or more capsas |
| `GetDecryptedCapsaAsync(capsaId)` | Fetch and decrypt a capsa |
| `GetCapsaAsync(capsaId)` | Fetch a capsa without decryption |
| `ListCapsasAsync(filters?)` | List capsas with optional filters |
| `DeleteCapsaAsync(capsaId)` | Soft-delete a capsa |
| `DownloadFileAsync(capsaId, fileId)` | Download and decrypt a file |
| `GetAuditEntriesAsync(capsaId)` | Get audit trail entries |
| `AddPublicKeyAsync(key, fp, reason?)` | Register a new public key |
| `RotateKeyAsync()` | Generate and register a new key pair |
| `GetKeyHistoryAsync()` | Get previous public keys |
| `GetLimitsAsync()` | Get server-enforced limits |
| `Dispose()` | Release resources (`IDisposable`) |

## License

Capsara SDK License. See [LICENSE](./LICENSE) for details.
