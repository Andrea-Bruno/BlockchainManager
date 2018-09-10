using System;

namespace BlockchainManager
{
  // ================TEST AND EXAMPLES ==================
  static class Test
  {
    public static void Test_SimpleBlockchain()
    {
      // Simple blockchain

      Blockchain Blocks = new Blockchain("Webmaster", "Phrases", Blockchain.BlockchainType.Binary, Blockchain.BlockSynchronization.AddInLocalAndSync, false);
      var Test = Blocks.Validate();
      Blockchain.Block Block1 = new Blockchain.Block(Blocks, "Hi my friends, I have a message for you");
      Blockchain.Block Block2 = new Blockchain.Block(Blocks, "This is a message number 2");
      Blockchain.Block Block3 = new Blockchain.Block(Blocks, "In the last block I added the last message");
      int BlockError = Blocks.Validate(); // 0 = no error
      var LastBlock = Blocks.GetLastBlock();
    }

    public static void Test_BlockchainWithDocumentsSigned()
    {
      // Blockchain with the content having double signature

      System.Security.Cryptography.RSACryptoServiceProvider RSA1 = new System.Security.Cryptography.RSACryptoServiceProvider();
      var PublicKey1Base64 = Convert.ToBase64String(RSA1.ExportCspBlob(false));

      System.Security.Cryptography.RSACryptoServiceProvider RSA2 = new System.Security.Cryptography.RSACryptoServiceProvider();
      var PublicKey2Base64 = Convert.ToBase64String(RSA2.ExportCspBlob(false));

      Blockchain Blocks = new Blockchain("Webmaster", "Phrases", Blockchain.BlockchainType.Binary, Blockchain.BlockSynchronization.AddInLocalAndSync, true);
      var Test = Blocks.Validate();
      byte[] Signature;
      bool IsValid;

      Blockchain.Block Block1 = new Blockchain.Block(Blocks, "Hi my friends, I have a message for you");
      Signature = RSA1.SignHash(Block1.HashBody(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      IsValid = Block1.AddBodySignature(PublicKey1Base64, Signature, false); // Add first signature
      Signature = RSA2.SignHash(Block1.HashBody(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      IsValid = Block1.AddBodySignature(PublicKey2Base64, Signature, true); // Add second signature and closing the block

      Blockchain.Block Block2 = new Blockchain.Block(Blocks, "This is a message number 2, signed");
      Signature = RSA1.SignHash(Block2.HashBody(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      IsValid = Block2.AddBodySignature(PublicKey1Base64, Signature, false); // Add first signature
      Signature = RSA2.SignHash(Block2.HashBody(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      IsValid = Block2.AddBodySignature(PublicKey2Base64, Signature, true);

      Blockchain.Block Block3 = new Blockchain.Block(Blocks, "In the last block I added the last message");
      Signature = RSA1.SignHash(Block3.HashBody(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      IsValid = Block3.AddBodySignature(PublicKey1Base64, Signature, false); // Add first signature
      Signature = RSA2.SignHash(Block3.HashBody(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      IsValid = Block3.AddBodySignature(PublicKey2Base64, Signature, true); // Add second signature and closing the block

      int BlockError = Blocks.Validate(); // 0 = no error
      var LastBlock = Blocks.GetLastBlock();
    }

    public static void Test_BlockchainWithGlobalSignature()
    {
      // Blockchain whose block closure is guaranteed by digital signature
      System.Security.Cryptography.RSACryptoServiceProvider RSA = new System.Security.Cryptography.RSACryptoServiceProvider();

      var PublicKeyBase64 = Convert.ToBase64String(RSA.ExportCspBlob(false));
      var PrivateKeyBase64 = Convert.ToBase64String(RSA.ExportCspBlob(true));

      Blockchain Blocks = new Blockchain(new string[] { PublicKeyBase64 }, "Webmaster", "Phrases", Blockchain.BlockchainType.Binary, Blockchain.BlockSynchronization.AddInLocalAndSync, false);
      byte[] Signature;
      bool IsValid;

      Blockchain.Block Block1 = new Blockchain.Block(Blocks, "Hi my friends, I have a message for you");
      Signature = RSA.SignHash(Block1.CalculateChecksumBytes(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      IsValid = Block1.AddBlockSignature(Signature); // Close the block with the digital signature

      Blockchain.Block Block2 = new Blockchain.Block(Blocks, "This is a message number 2, signed");
      Signature = RSA.SignHash(Block2.CalculateChecksumBytes(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      IsValid = Block2.AddBlockSignature(Signature); // Close the block with the digital signature

      Blockchain.Block Block3 = new Blockchain.Block(Blocks, "In the last block I added the last message");
      Signature = RSA.SignHash(Block3.CalculateChecksumBytes(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      IsValid = Block3.AddBlockSignature(Signature); // Close the block with the digital signature

      int BlockError = Blocks.Validate(); // 0 = no error
      var LastBlock = Blocks.GetLastBlock();
    }

    public static void Test_BlockchainWithDocumentsSignedAndGlobalSignature()
    {
      // Blockchain with the content having double signature and the block closure is guaranteed by digital signature

      System.Security.Cryptography.RSACryptoServiceProvider RSA = new System.Security.Cryptography.RSACryptoServiceProvider();
      var PublicKeyBase64 = Convert.ToBase64String(RSA.ExportCspBlob(false));

      Blockchain Blocks = new Blockchain(new string[] { PublicKeyBase64 }, "Webmaster", "Phrases", Blockchain.BlockchainType.Binary, Blockchain.BlockSynchronization.AddInLocalAndSync, true);
      var Test = Blocks.Validate();
      byte[] Signature;
      bool IsValid;

      Blockchain.Block Block1 = new Blockchain.Block(Blocks, "Hi my friends, I have a message for you");
      Signature = RSA.SignHash(Block1.HashBody(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      IsValid = Block1.AddBodySignature(PublicKeyBase64, Signature, false); // Add signature to body
      Signature = RSA.SignHash(Block1.CalculateChecksumBytes(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      IsValid = Block1.AddBlockSignature(Signature); // Close the block with the digital signature

      Blockchain.Block Block2 = new Blockchain.Block(Blocks, "This is a message number 2, signed");
      Signature = RSA.SignHash(Block2.HashBody(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      IsValid = Block2.AddBodySignature(PublicKeyBase64, Signature, false); // Add signature to body
      Signature = RSA.SignHash(Block2.CalculateChecksumBytes(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      IsValid = Block2.AddBlockSignature(Signature); // Close the block with the digital signature

      Blockchain.Block Block3 = new Blockchain.Block(Blocks, "In the last block I added the last message");
      Signature = RSA.SignHash(Block3.HashBody(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      IsValid = Block3.AddBodySignature(PublicKeyBase64, Signature, false); // Add signature to body
      Signature = RSA.SignHash(Block3.CalculateChecksumBytes(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
      IsValid = Block3.AddBlockSignature(Signature); // Close the block with the digital signature

      int BlockError = Blocks.Validate(); // 0 = no error
      var LastBlock = Blocks.GetLastBlock();
    }

  }
}
