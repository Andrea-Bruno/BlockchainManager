using System;

namespace BlockchainManager
{
  // ================TEST AND EXAMPLES ==================
  internal static class Test
  {
    public static void Test_SimpleBlockchain()
    {
      // Simple blockchain

      var blocks = new Blockchain("Webmaster", "Phrases", Blockchain.BlockchainType.Binary, Blockchain.BlockSynchronization.AddInLocalAndSync, false);
      var test = blocks.Validate();
      var block1 = new Blockchain.Block(blocks, "Hi my friends, I have a message for you");
      var block2 = new Blockchain.Block(blocks, "This is a message number 2");
      var block3 = new Blockchain.Block(blocks, "In the last block I added the last message");
      var blockError = blocks.Validate(); // 0 = no error
      var lastBlock = blocks.GetLastBlock();
    }

    public static void Test_BlockchainWithDocumentsSigned()
    {
      // Blockchain with the content having double signature

      var rsa1 = new System.Security.Cryptography.RSACryptoServiceProvider();
      var publicKey1Base64 = Convert.ToBase64String(rsa1.ExportCspBlob(false));

      var rsa2 = new System.Security.Cryptography.RSACryptoServiceProvider();
      var publicKey2Base64 = Convert.ToBase64String(rsa2.ExportCspBlob(false));

      var blocks = new Blockchain("Webmaster", "Phrases", Blockchain.BlockchainType.Binary, Blockchain.BlockSynchronization.AddInLocalAndSync, true);
      var test = blocks.Validate();
      bool isValid;

      var block1 = new Blockchain.Block(blocks, "Hi my friends, I have a message for you");
      var signature = rsa1.SignHash(block1.HashBody(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      isValid = block1.AddBodySignature(publicKey1Base64, signature, false); // Add first signature
      signature = rsa2.SignHash(block1.HashBody(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      isValid = block1.AddBodySignature(publicKey2Base64, signature, true); // Add second signature and closing the block

      var block2 = new Blockchain.Block(blocks, "This is a message number 2, signed");
      signature = rsa1.SignHash(block2.HashBody(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      isValid = block2.AddBodySignature(publicKey1Base64, signature, false); // Add first signature
      signature = rsa2.SignHash(block2.HashBody(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      isValid = block2.AddBodySignature(publicKey2Base64, signature, true);

      var block3 = new Blockchain.Block(blocks, "In the last block I added the last message");
      signature = rsa1.SignHash(block3.HashBody(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      isValid = block3.AddBodySignature(publicKey1Base64, signature, false); // Add first signature
      signature = rsa2.SignHash(block3.HashBody(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      isValid = block3.AddBodySignature(publicKey2Base64, signature, true); // Add second signature and closing the block

      var blockError = blocks.Validate(); // 0 = no error
      var lastBlock = blocks.GetLastBlock();
    }

    public static void Test_BlockchainWithGlobalSignature()
    {
      // Blockchain whose block closure is guaranteed by digital signature
      var rsa = new System.Security.Cryptography.RSACryptoServiceProvider();

      var publicKeyBase64 = Convert.ToBase64String(rsa.ExportCspBlob(false));
      var privateKeyBase64 = Convert.ToBase64String(rsa.ExportCspBlob(true));

      var blocks = new Blockchain(new string[] { publicKeyBase64 }, "Webmaster", "Phrases", Blockchain.BlockchainType.Binary, Blockchain.BlockSynchronization.AddInLocalAndSync, false);
      bool isValid;

      var block1 = new Blockchain.Block(blocks, "Hi my friends, I have a message for you");
      var signature = rsa.SignHash(block1.CalculateChecksumBytes(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      isValid = block1.AddBlockSignature(signature); // Close the block with the digital signature

      var block2 = new Blockchain.Block(blocks, "This is a message number 2, signed");
      signature = rsa.SignHash(block2.CalculateChecksumBytes(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      isValid = block2.AddBlockSignature(signature); // Close the block with the digital signature

      var block3 = new Blockchain.Block(blocks, "In the last block I added the last message");
      signature = rsa.SignHash(block3.CalculateChecksumBytes(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      isValid = block3.AddBlockSignature(signature); // Close the block with the digital signature

      var blockError = blocks.Validate(); // 0 = no error
      var lastBlock = blocks.GetLastBlock();
    }

    public static void Test_BlockchainWithDocumentsSignedAndGlobalSignature()
    {
      // Blockchain with the content having double signature and the block closure is guaranteed by digital signature

      var rsa = new System.Security.Cryptography.RSACryptoServiceProvider();
      var publicKeyBase64 = Convert.ToBase64String(rsa.ExportCspBlob(false));

      var blocks = new Blockchain(new[] { publicKeyBase64 }, "Webmaster", "Phrases", Blockchain.BlockchainType.Binary, Blockchain.BlockSynchronization.AddInLocalAndSync, true);
      var test = blocks.Validate();
      bool isValid;

      var block1 = new Blockchain.Block(blocks, "Hi my friends, I have a message for you");
      var signature = rsa.SignHash(block1.HashBody(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      isValid = block1.AddBodySignature(publicKeyBase64, signature, false); // Add signature to body
      signature = rsa.SignHash(block1.CalculateChecksumBytes(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      isValid = block1.AddBlockSignature(signature); // Close the block with the digital signature

      var block2 = new Blockchain.Block(blocks, "This is a message number 2, signed");
      signature = rsa.SignHash(block2.HashBody(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      isValid = block2.AddBodySignature(publicKeyBase64, signature, false); // Add signature to body
      signature = rsa.SignHash(block2.CalculateChecksumBytes(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      isValid = block2.AddBlockSignature(signature); // Close the block with the digital signature

      var block3 = new Blockchain.Block(blocks, "In the last block I added the last message");
      signature = rsa.SignHash(block3.HashBody(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      isValid = block3.AddBodySignature(publicKeyBase64, signature, false); // Add signature to body
      signature = rsa.SignHash(block3.CalculateChecksumBytes(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      isValid = block3.AddBlockSignature(signature); // Close the block with the digital signature

      var blockError = blocks.Validate(); // 0 = no error
      var lastBlock = blocks.GetLastBlock();
    }

  }
}
