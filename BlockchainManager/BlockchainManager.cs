using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Xml.Serialization;
using NetworkManager;

namespace BlockchainManager
{
  public static class NetworkInitializer
  {
    public static Network CurrentNetwork { get; private set; }

    internal static List<Network> HookedNetworks = new List<Network>();

    /// <summary>
    ///   The new Blockchain instances will all be created on the selected network.
    ///   Use this function to change the current network.
    ///   By default, the current network will be the last initialized network.
    /// </summary>
    /// <param name="index">Select the network with this Index</param>
    public static void ChooseCurrentNetwork(int index)
    {
      try
      {
        CurrentNetwork = HookedNetworks[index];
      }
      catch (Exception)
      {
        throw new Exception("No network with this name has been initialized");
      }
    }

    /// <summary>
    ///   The new Blockchain instances will all be created on the current network.
    ///   Use this function to change the current network.
    ///   By default, the current network will be the last initialized network.
    /// </summary>
    /// <param name="network">The new current Network</param>
    public static void SetCurrentNetwork(Network network)
    {
      CurrentNetwork = network;
    }

    /// <summary>
    ///   This method initializes a new network class.
    ///   A network is a p2p network made up of multiple nodes.
    ///   By repeating this command, you can link to multiple networks to use or participate in different networks
    ///   simultaneously.
    ///   You can join the network as a node, and contribute to decentralization, or hook yourself to the network as an
    ///   external user.
    ///   To create a node, set the MyAddress parameter with your web address.If MyAddress is not set then you are an external
    ///   user.
    /// </summary>
    /// <param name="entryPoints">
    ///   Value pairs Address and MachineName: The list of permanent access points nodes, to access the
    ///   network
    /// </param>
    /// <param name="networkName">The name of the infrastructure. For tests we recommend using "testnet"</param>
    /// <param name="myNode">Data related to your node. If you do not want to create the node, omit this parameter</param>
    public static Network HookToNetwork(Dictionary<string, string> entryPoints, string networkName = "testnet",
      NodeInitializer myNode = null)
    {
      //#if DEBUG
      //      //NodeList = new Node[1] { new Node() { Server = "http://www.bitboxlab.com", MachineName = "ANDREA", PublicKey = "" } };
      //      NodeList = new Node[1] { new Node() { Server = "http://localhost:55007", MachineName = Environment.MachineName, PublicKey = "" } };
      //#else
      //        NodeList = new Node[1] { new Node() { Server = "http://www.bitboxlab.com", MachineName = "ANDREA", PublicKey = "" } };
      //#endif
      //if (HookedNetworks.ContainsKey(NetworkName))
      //  throw new Exception("Node already hooked");
      try
      {
        Node[] nodes = null;
        if (entryPoints != null)
        {
          var nodeList = new List<Node>();
          foreach (var entry in entryPoints)
            nodeList.Add(new Node { Address = entry.Key, MachineName = entry.Value });
          nodes = nodeList.ToArray();
        }

        var network = new Network(nodes, networkName, myNode);
        SetNetwork(network);
        HookedNetworks.Add(network);
        CurrentNetwork = network;
        return network;
      }
      catch (Exception ex)
      {
        Debug.Print(ex.Message);
        Debugger.Break();
        return null;
      }
    }

    private static bool SetNetwork(Network network)
    {
      network.AddSyncDataFromBufferAction(ActionSync, "DataVector");
      return network.Protocol.AddOnReceivingObjectAction("VectorBlocks", Blockchain.GetVectorBlocks);
    }

    private static void ActionSync(string xmlObject, long timestamp)
    {
      if (!Converter.XmlToObject(xmlObject, typeof(Blockchain.Block.DataVector), out var objDataVector)) return;
      var dataVector = (Blockchain.Block.DataVector)objDataVector;
      var block = new Blockchain.Block(dataVector.Blockchain, dataVector.Data, new DateTime(timestamp));
    }
  }

  public class Blockchain
  {
    public Blockchain()
    {
      _network = NetworkInitializer.CurrentNetwork;
    }

    public Blockchain(string[] publicKeys, string @group, string name, BlockchainType type,
      BlockSynchronization synchronizationType, bool acceptBodySignature, int maxBlockLenght = 2048,
      double daysExpiredAfterInactivity = 30)
    {
      _network = NetworkInitializer.CurrentNetwork;
      PublicKeys = publicKeys;
      Group = @group;
      Name = name;
      Type = type;
      SynchronizationType = synchronizationType;
      AcceptBodySignature = acceptBodySignature;
      MaxBlockLenght = maxBlockLenght;
      ExpiredAfterInactivity = TimeSpan.FromDays(daysExpiredAfterInactivity);
    }

    public Blockchain(string @group, string name, BlockchainType type, BlockSynchronization synchronizationType,
      bool acceptBodySignature, int maxBlockLenght = 2048, double daysExpiredAfterInactivity = 30)
    {
      _network = NetworkInitializer.CurrentNetwork;
      Group = @group;
      Name = name;
      Type = type;
      SynchronizationType = synchronizationType;
      AcceptBodySignature = acceptBodySignature;
      MaxBlockLenght = maxBlockLenght;
      ExpiredAfterInactivity = TimeSpan.FromDays(daysExpiredAfterInactivity);
    }

    private readonly Network _network;

    public void Save()
    {
      if (!System.IO.Directory.Exists(Directory()))
        System.IO.Directory.CreateDirectory(Directory());
      using (var stream = new FileStream(PathNameFile() + ".info", FileMode.Create))
      {
        var xml = new XmlSerializer(GetType());
        var xmlns = new XmlSerializerNamespaces();
        xmlns.Add(string.Empty, string.Empty);
        xml.Serialize(stream, this, xmlns);
      }
    }

    public static Blockchain Load(string @group, string name)
    {
      try
      {
        var file = PathNameFile(NetworkInitializer.CurrentNetwork, @group, name) + ".info";
        Blockchain value;
        if (File.Exists(file))
        {
          using (var stream = new FileStream(file, FileMode.Open, FileAccess.Read))
          {
            var xml = new XmlSerializer(typeof(Blockchain));
            value = (Blockchain)xml.Deserialize(stream);
          }

          return value;
        }
      }
      catch (Exception ex)
      {
        Debug.Print(ex.Message);
        Debugger.Break();
      }

      return null;
    }

    public bool AcceptBodySignature;
    public TimeSpan ExpiredAfterInactivity;

    public string PublicKey
    {
      set => PublicKeys = new string[1] { value };
    }

    /// <summary>
    ///   List of private key authorized to sign the block:
    ///   If is not null then all block Checksum are signed with one of this private key
    /// </summary>
    public string[] PublicKeys;

    public string Group;
    public string Name;

    /// <summary>
    ///   How the blocks will be synchronized on the blockchain
    /// </summary>
    public BlockSynchronization SynchronizationType;

    /// <summary>
    ///   If you use the AddInLocalAndSync mode, make sure that no blocks are added simultaneously.
    ///   If you use SendToTheNetworkBuffer mode, the network will add blocks to the blockchain.
    /// </summary>
    public enum BlockSynchronization
    {
      AddInLocalAndSync,
      SendToTheNetworkBuffer
    }

    public BlockchainType Type;

    public enum BlockchainType
    {
      LineOfText,
      Xml,
      Binary
    }

    public int MaxBlockLenght = 2048;
    private const int LenghtDataTrasmission = 1024 * 1024 * 20; //20 mega;
    private const string BlockSeparator = "\r\n";
    private const string FieldsSeparator = "\t";

    public long Length()
    {
      return File.Exists(PathNameFile()) ? new FileInfo(PathNameFile()).Length : 0;
    }

    public void Truncate(long position)
    {
      using (var stream = new FileStream(PathNameFile(), FileMode.Truncate))
      {
        stream.SetLength(position);
      }
    }

    internal static object GetVectorBlocks(string xmlVectorBlocks)
    {
      object returnObject;
      Converter.XmlToObject(xmlVectorBlocks, typeof(VectorBlocks), out var obj);
      var vectorBlocks = (VectorBlocks)obj;
      var returnVectorBlocks = new VectorBlocks();
      if (UpdateLocalBlockchain(vectorBlocks, returnVectorBlocks))
        returnObject = returnVectorBlocks;
      else
        returnObject = "error: blockchain corrupted";
      return returnObject;
    }

    /// <summary>
    ///   This object is used to send or receive blocks
    ///   To receive the blocks from the remote server, set the RequestSendBlocksFromPosition parameter
    ///   The parameter Position indicates the position in the blockchain of the inserted vector blocks
    ///   Position is base 0
    /// </summary>
    public class VectorBlocks
    {
      public VectorBlocks()
      {
      }

      public VectorBlocks(Blockchain blockchain)
      {
        Blockchain = blockchain;
      }

      public Blockchain Blockchain;
      public long Position = -1; //Base 0

      /// <summary>
      ///   Ask to receive blocks from the Base 0 position, if this value is -1 then there is no request
      /// </summary>
      public long RequestSendBlocksFromPosition = -1;

      public ReadBlocksResult ReadBlocksResult;

      public List<Block> Blocks
      {
        set
        {
          var list = new List<string>();
          foreach (var block in value)
            list.Add(block.Record);
          Records = list.ToArray();
        }
      }

      public string[] Records;
    }

    /// <summary>
    ///   Synchronize the local blockchain, with the nodes remotely
    /// </summary>
    /// <returns>Returns False if the operation fails</returns>
    public bool RequestAnyNewBlocks()
    {
      return _network.InteractWithRandomNode(node =>
      {
        try
        {
          var currentLength = Length();
          var vector = new VectorBlocks { Blockchain = this, RequestSendBlocksFromPosition = currentLength };
          VectorToNode(vector, node.Address, node.MachineName);
          return true;
        }
        catch (Exception ex)
        {
          Debug.Print(ex.Message);
          Debugger.Break();
          return false;
        }
      });
    }

    private void VectorToNode(VectorBlocks vector, string server, string machineName)
    {
      VectorBlocks returnVector;
      do
      {
        returnVector = null;
        object obj;
        var xmlObjectVector = _network.Comunication.SendObjectSync(vector, server, null, machineName);
        if (string.IsNullOrEmpty(xmlObjectVector)) continue;
        Converter.XmlToObject(xmlObjectVector, typeof(Comunication.ObjectVector), out var returmObj);
        var objVector = (Comunication.ObjectVector)returmObj;
        var returnObjectName = objVector.ObjectName;
        var returnXmlObject = objVector.XmlObject;
        if (returnObjectName == "VectorBlocks")
        {
          Converter.XmlToObject(returnXmlObject, typeof(VectorBlocks), out obj);
          returnVector = (VectorBlocks)obj;
          if (returnVector.Blockchain == null)
            returnVector.Blockchain = vector.Blockchain;
          if (returnVector.RequestSendBlocksFromPosition != -1)
          {
            var blocksToSend = GetBlocks(returnVector.RequestSendBlocksFromPosition, out var readBlocksResult);
            var vectorToSend = new VectorBlocks
            {
              Blockchain = this,
              Blocks = blocksToSend,
              Position = returnVector.RequestSendBlocksFromPosition,
              ReadBlocksResult = readBlocksResult
            };
            VectorToNode(vectorToSend, server, machineName);
          }
          else
          {
            vector = new VectorBlocks(); //Used to repeat the operation in case of partial reception of blocks
            UpdateLocalBlockchain(returnVector, vector);
          }
        }
        else
        {
          Converter.XmlToObject(returnXmlObject, typeof(string), out obj);
          var errorMessage = Convert.ToString(obj);
          Utility.Log("BlockchainError", errorMessage);
        }
      } while (returnVector != null && returnVector.ReadBlocksResult == ReadBlocksResult.Partial);
    }

    /// <summary>
    ///   Send a locally block it to the nodes of the network
    /// </summary>
    /// <param name="block">The block</param>
    /// <returns>Returns False if the operation fails</returns>
    public bool SendBlockToNetwork(Block block)
    {
      return SyncBlocksToNetwork(new List<Block> { block }, -1);
    }

    /// <summary>
    ///   Send locally blocks it to the nodes of the network
    /// </summary>
    /// <param name="blocks">The blocks</param>
    /// <returns>Returns False if the operation fails</returns>
    public bool SendBlocksToNetwork(List<Block> blocks)
    {
      return SyncBlocksToNetwork(blocks, -1);
    }

    /// <summary>
    ///   Synchronize a block written locally and transmit it to the nodes of the network
    /// </summary>
    /// <param name="block">The block</param>
    /// <param name="position">Base 0 position</param>
    /// <returns>Returns False if the operation fails</returns>
    public bool SyncBlockToNetwork(Block block, long position)
    {
      return SyncBlocksToNetwork(new List<Block> { block }, position);
    }

    /// <summary>
    ///   Synchronize the blocks written locally and transmit it to the nodes of the network
    /// </summary>
    /// <param name="blocks">The blocks</param>
    /// <param name="position">Base 0 position</param>
    /// <returns>Returns False if the operation fails</returns>
    public bool SyncBlocksToNetwork(List<Block> blocks, long position)
    {
      return _network.InteractWithRandomNode(node =>
      {
        try
        {
          var vector = new VectorBlocks { Blockchain = this, Blocks = blocks, Position = position };
          if (node.MachineName != _network.MachineName)
            VectorToNode(vector, node.Address, node.MachineName);
          return true;
        }
        catch (Exception ex)
        {
          Debug.Print(ex.Message);
          Debugger.Break();
          return false;
        }
      });
    }

    /// <summary>
    ///   Add to the local blockchain the blocks received from the server
    ///   This function is normally called by the Page.Load event when a Vector is received remotely
    /// </summary>
    /// <param name="vector">Parameter that is used to send blocks or to request blocks</param>
    /// <param name="setReturnVector">
    ///   This parameter returns a vector containing possible blocks to be synchronized on the
    ///   local blockchain
    /// </param>
    /// <returns>Returns False if the operation fails</returns>
    public static bool UpdateLocalBlockchain(VectorBlocks vector, VectorBlocks setReturnVector = null)
    {
      var blockchain = vector.Blockchain;
      var currentLength = blockchain.Length();
      if (currentLength == 0)
        blockchain.Save();

      if (vector.RequestSendBlocksFromPosition != -1 && setReturnVector != null)
      {
        if (currentLength > vector.RequestSendBlocksFromPosition)
        {
          setReturnVector.Blockchain = blockchain;
          setReturnVector.Blocks =
            blockchain.GetBlocks(vector.RequestSendBlocksFromPosition, out setReturnVector.ReadBlocksResult);
          setReturnVector.Position = vector.RequestSendBlocksFromPosition;
        }
        else if (currentLength < vector.RequestSendBlocksFromPosition)
        {
          setReturnVector.Blockchain = blockchain;
          setReturnVector.RequestSendBlocksFromPosition = currentLength;
        }
      }
      else if (vector.Position != -1)
      {
        if (currentLength > vector.Position)
        {
          if (setReturnVector != null)
          {
            setReturnVector.Blockchain = blockchain;
            setReturnVector.Blocks = blockchain.GetBlocks(vector.Position, out setReturnVector.ReadBlocksResult);
            setReturnVector.Position = vector.Position;
          }
          else
          {
            blockchain.Truncate(vector.Position);
            currentLength = vector.Position;
          }
        }

        if (currentLength == vector.Position)
        {
          if (vector.Records.Any(record => !blockchain.AddRecord(record)))
            return false;
          if (vector.ReadBlocksResult != ReadBlocksResult.Partial) return true;
          if (setReturnVector == null) return true;
          setReturnVector.Blockchain = blockchain;
          setReturnVector.RequestSendBlocksFromPosition = blockchain.Length();
        }
        else if (currentLength < vector.Position)
        {
          // Send a request of th missed blocks 
          if (setReturnVector == null) return true;
          setReturnVector.Blockchain = blockchain;
          setReturnVector.RequestSendBlocksFromPosition = currentLength;
        }
      }

      return true;
    }

    public class Block
    {
      private Block()
      {
      }

      /// <summary>
      ///   Instantiate a block from a record of data written on the blockchain.
      ///   It is used to read the blockchain.
      /// </summary>
      /// <param name="previousBlock">The previous block</param>
      /// <param name="blockchain">The blockchain</param>
      /// <param name="record">
      ///   The record is the entire data package that represents the block, includes the possible signature
      ///   and checksum
      /// </param>
      public Block(Block previousBlock, Blockchain blockchain, string record)
      {
        _previousBlock = previousBlock;
        _blockchain = blockchain;
        Record = record;
      }

      /// <summary>
      ///   Create a block that will be immediately added to the blockchain.
      ///   If the blockchain has set a public key, then the block will not be added now, but will need to be added later once
      ///   the signature is added
      /// </summary>
      /// <param name="blockchain">The Blockchain used</param>
      /// <param name="data">The data to be included in the block</param>
      public Block(Blockchain blockchain, byte[] data)
      {
        _Block(blockchain, Convert.ToBase64String(data));
      }

      /// <summary>
      ///   Create a block that will be immediately added to the blockchain.
      ///   If the blockchain has set a public key, then the block will not be added now, but will need to be added later once
      ///   the signature is added
      /// </summary>
      /// <param name="blockchain">The Blockchain used</param>
      /// <param name="data">The data to be included in the block</param>
      public Block(Blockchain blockchain, string data)
      {
        switch (blockchain.Type)
        {
          case BlockchainType.Xml:
            data = data.Replace("\n", "").Replace("\r", "");
            break;
          case BlockchainType.Binary:
            throw new InvalidOperationException("Invalid method with the blockchain in binary mode");
          case BlockchainType.LineOfText:
            break;
          default:
            throw new ArgumentOutOfRangeException();
        }

        _Block(blockchain, data);
      }

      /// <summary>
      ///   Use this method only for data that exits from shared buffer
      /// </summary>
      /// <param name="blockchain"></param>
      /// <param name="data"></param>
      /// <param name="timestamp">The timestam assigned by the buffer</param>
      internal Block(Blockchain blockchain, string data, DateTime timestamp)
      {
        _Block(blockchain, data, timestamp, true);
      }

      /// <summary>
      ///   Set a block that will be immediately added to the blockchain.
      ///   If the blockchain has set a public key, then the block will not be added now, but will need to be added later once
      ///   the signature is added
      /// </summary>
      /// <param name="blockchain">The Blockchain used</param>
      /// <param name="data">The data to be included in the block</param>
      /// <param name="timestamp">The timestamp</param>
      /// <param name="local">Add block in local</param>
      private void _Block(Blockchain blockchain, string data, DateTime timestamp = default(DateTime),
        bool local = false)
      {
        _blockchain = blockchain;
        _data = data;
        Timestamp = timestamp != default(DateTime) ? timestamp : DateTime.Now.ToUniversalTime();
        if (local || blockchain.SynchronizationType == BlockSynchronization.AddInLocalAndSync)
        {
          _previousBlock = blockchain.GetLastBlock();
          Checksum = CalculateChecksum();
          if (blockchain.AcceptBodySignature) return;
          if (blockchain.PublicKeys == null)
            AddToBlockchain();
        }
        else
        {
          var vector = new DataVector { Data = data, Blockchain = blockchain };
          blockchain._network.AddToSaredBuffer(vector);
          //Blockchain.SendBlockToNetwork(this);
        }
      }

      /// <summary>
      ///   This element is used to send the data inserted in the block to the shared buffer
      /// </summary>
      public class DataVector
      {
        public Blockchain Blockchain;
        public string Data;
      }

      private Block _previousBlock;

      public bool AddBlockSignature(byte[] signedChecksum)
      {
        Checksum = Convert.ToBase64String(signedChecksum);
        var result = CheckBlockSignature();
        if (result)
          AddToBlockchain();
        return result;
      }

      public bool CheckBlockSignature()
      {
        try
        {
          foreach (var publicKey in _blockchain.PublicKeys)
          {
            var rsAalg = new RSACryptoServiceProvider();
            rsAalg.ImportCspBlob(Convert.FromBase64String(publicKey));
            if (rsAalg.VerifyHash(CalculateChecksumBytes(), CryptoConfig.MapNameToOID("SHA256"), ChecksumBytes))
              return true;
          }

          return false;
        }
        catch (Exception ex)
        {
          Debug.Print(ex.Message);
          Debugger.Break();
          return false;
        }
      }

      private byte[] BaseChecksum()
      {
        string previousChecksum = null;
        if (_previousBlock != null)
          previousChecksum = _previousBlock.Checksum;
        var baseComputation = BodyRecord(true);
        return Encoding.Unicode.GetBytes(previousChecksum + baseComputation);
      }

      public byte[] CalculateChecksumBytes()
      {
        HashAlgorithm hashType = new SHA256Managed();
        var hashBytes = hashType.ComputeHash(BaseChecksum());
        return hashBytes;
      }

      private string CalculateChecksum()
      {
        return Convert.ToBase64String(CalculateChecksumBytes());
      }

      public bool IsValid()
      {
        if (CheckBodySignatures())
        {
          return _blockchain.PublicKeys != null ? CheckBlockSignature() : Checksum == CalculateChecksum();
        }

        return false;
      }

      private Blockchain _blockchain;

      public bool AddToBlockchain(Blockchain blockchain = null)
      {
        if (_blockchain == null)
          _blockchain = blockchain;
        return _blockchain != null && _blockchain.AddBlock(this);
      }

      internal bool AddedToBlockchain;
      private string _data;

      public string Data
      {
        get
        {
          if (_blockchain.Type == BlockchainType.Binary)
            throw new InvalidOperationException("Invalid method with the blockchain in binary mode");
          return _data;
        }
      }

      public byte[] DataByteArray
      {
        get
        {
          if (_blockchain.Type != BlockchainType.Binary)
            throw new InvalidOperationException("Invalid method with the blockchain is not in binary mode");
          return Convert.FromBase64String(_data);
        }
      }

      public DateTime Timestamp { get; private set; }
      public string Checksum { get; private set; }

      public byte[] ChecksumBytes => Convert.FromBase64String(Checksum);
      private string _bodySignatures;

      /// <summary>
      ///   Returns a dictionary indexed with public keys, and the values of the block signatures
      /// </summary>
      /// <returns></returns>
      public Dictionary<string, string> GetAllBodySignature()
      {
        if (string.IsNullOrEmpty(_bodySignatures)) return null;
        var result = new Dictionary<string, string>();
        var parts = _bodySignatures.Split(' ');
        string publicKey = null;
        var flag = false;
        foreach (var part in parts)
        {
          if (flag)
          {
            var signature = part;
            result.Add(publicKey, signature);
          }
          else
          {
            publicKey = part;
          }

          flag = !flag;
        }

        return result;
      }

      public bool AddBodySignature(string publicKey, byte[] signature, bool addNowToBlockchain)
      {
        if (_blockchain.AcceptBodySignature)
        {
          if (!CheckBodySignature(publicKey, signature)) return false;
          if (!string.IsNullOrEmpty(_bodySignatures))
            _bodySignatures += " ";
          _bodySignatures += publicKey + " " + Convert.ToBase64String(signature);
          Checksum = CalculateChecksum();
          return !addNowToBlockchain || AddToBlockchain();
        }
        else
        {
          throw new Exception("This blockchain does not allow to add signatures to the body");
        }
        //return false;
      }

      public bool CheckBodySignatures()
      {
        var signatures = GetAllBodySignature();
        if (signatures == null) return true;
        foreach (var pubKey in signatures.Keys)
          if (!CheckBodySignature(pubKey, Convert.FromBase64String(signatures[pubKey])))
            return false;
        return true;
      }

      private bool CheckBodySignature(string publicKey, byte[] signature)
      {
        try
        {
          var rsAalg = new RSACryptoServiceProvider();
          rsAalg.ImportCspBlob(Convert.FromBase64String(publicKey));
          return rsAalg.VerifyHash(HashBody(), CryptoConfig.MapNameToOID("SHA256"), signature);
        }
        catch (Exception e)
        {
          Console.WriteLine(e.Message);
          return false;
        }
      }

      public byte[] HashBody()
      {
        HashAlgorithm hashType = new SHA256Managed();
        var hashBytes = hashType.ComputeHash(Encoding.Unicode.GetBytes(BodyRecord(false)));
        return hashBytes;
      }

      private string BodyRecord(bool withSigatures)
      {
        var hexTimestamp = Timestamp.Ticks.ToString("X");
        if (!withSigatures) return _data + FieldsSeparator + hexTimestamp;
        var signatures = string.IsNullOrEmpty(_bodySignatures) ? null : FieldsSeparator + _bodySignatures ;
        return _data + FieldsSeparator + hexTimestamp + signatures;
      }

      protected internal string Record
      {
        get => BodyRecord(true) + FieldsSeparator + Checksum;
        set
        {
          if (string.IsNullOrEmpty(value)) return;
          // ===========PARTS==========================
          // Data + Timestamp + (Signatures) + Checksum
          // ==========================================
          var parts = value.Split(new[] { FieldsSeparator }, StringSplitOptions.None);
          //if (Blockchain.Type != BlockchainType.LineOfText)
          //  _Data = Converter.Base64ToString(Parts[0]);
          //else
          _data = parts[0];
          var dateHex = parts[1];
          Timestamp = new DateTime(Convert.ToInt64(dateHex, 16));
          if (parts.Count() == 4)
            _bodySignatures = parts[2];
          Checksum = parts.Last();
        }
      }
    }

    private static string MapPath(string pathNameFile)
    {
      //return System.IO.Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.ApplicationData), PathNameFile);
      var path = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
      return Path.Combine(path, pathNameFile);
    }

    private static string Directory(Network network, string @group)
    {
      return MapPath(Path.Combine(Setup.Ambient.Repository, AbjustNameFile(network.NetworkName),
        AbjustNameFile(@group)));
    }

    private string Directory()
    {
      return Directory(_network, Group);
    }

    private static string PathNameFile(Network network, string @group, string name)
    {
      return Path.Combine(Directory(network, @group), AbjustNameFile(name) + ".bloks");
    }

    private string PathNameFile()
    {
      return Path.Combine(Directory(), AbjustNameFile(Name) + ".bloks");
    }

    private static string AbjustNameFile(string fileName)
    {
      var result = "";
      foreach (var c in fileName)
        if (char.IsLetterOrDigit(c) || "+-=._".Contains(c))
          result += c;
        else
          result += "(" + string.Format("{0:X}", Convert.ToInt32(c)) + ")";
      return result;
    }

    public Block GetLastBlock()
    {
      return GetPreviousBlock(-1);
    }

    /// <summary>
    ///   Returns the block preceding the position on file Position, the parameter Position is base 0
    /// </summary>
    /// <param name="position">File position base 0, if Position is -1 then return the last block in blockchain</param>
    /// <returns></returns>
    public Block GetPreviousBlock(long position)
    {
      var file = PathNameFile();
      if (!File.Exists(file)) return null;
      string data = null;
      StreamReader stream = null;
      var nTryError = 0;
      try
      {
        stream = new StreamReader(file);
        if (position == -1)
          position = stream.BaseStream.Length;
        var startRead = position - MaxBlockLenght;
        if (startRead < 0)
          startRead = 0;
        stream.BaseStream.Position = startRead;

        var len = (int)(position - startRead);
        var buffer = new char[len];
        stream.Read(buffer, 0, len);
        data = new string(buffer);
      }
      catch (Exception ex)
      {
        Debug.Print(ex.Message);
        Debugger.Break();
        nTryError += 1;
        Thread.Sleep(500);
      }
      finally
      {
        if (stream != null)
        {
          stream.Close();
          stream.Dispose();
        }
      }
      if (string.IsNullOrEmpty(data)) return null;
      var blocks = data.Split(new[] { BlockSeparator }, StringSplitOptions.None);
      var block = blocks[blocks.Count() - 2];
      return new Block(null, this, block);
    }

    public int Validate()
    {
      // Return 0 = No error, else return the block number with error
      Block lastBlock = null;
      var invalidBlock = 0;
      if (!File.Exists(PathNameFile())) return invalidBlock;
      using (var stream = File.OpenText(PathNameFile()))
      {
        var n = 0;
        while (!stream.EndOfStream)
        {
          n += 1;
          var record = stream.ReadLine();
          var block = new Block(lastBlock, this, record);
          if (!block.IsValid())
          {
            invalidBlock = n;
            break;
          }

          lastBlock = block;
        }
      }

      return invalidBlock;
    }

    public List<Block> GetBlocks(long fromPosition, out ReadBlocksResult feedback)
    {
      var blocks = new List<Block>();
      Action<Block> execute = delegate (Block block) { blocks.Add(block); };
      feedback = ReadBlocks(fromPosition, execute, LenghtDataTrasmission);
      return blocks;
    }

    public ReadBlocksResult ReadBlocks(long fromPosition, Action<Block> execute, long exitAtLengthData = 0)
    {
      //List<Block> List = new List<Block>();
      long lengthData = 0;
      var lastBlock = GetPreviousBlock(fromPosition);
      if (!File.Exists(PathNameFile())) return ReadBlocksResult.Completed;
      using (var stream = File.OpenText(PathNameFile()))
      {
        stream.BaseStream.Position = fromPosition;
        while (!stream.EndOfStream)
        {
          var record = stream.ReadLine();
          lengthData += record.Length;
          var block = new Block(lastBlock, this, record);
          if (!block.IsValid())
            // Blockchain error!
            return ReadBlocksResult.Error;
          //List.Add(Block);
          execute(block);
          if (exitAtLengthData != 0)
            if (lengthData >= exitAtLengthData)
              return ReadBlocksResult.Partial;
          lastBlock = block;
        }
      }

      return ReadBlocksResult.Completed;
      //return List;
    }

    public enum ReadBlocksResult
    {
      Completed,
      Partial,
      Error
    }

    private bool AddBlock(Block block)
    {
      if (block.AddedToBlockchain)
        throw new InvalidOperationException("The block has already been added to the blockchain");
      if (!AddRecord(block.Record)) return false;
      block.AddedToBlockchain = true;
      return true;
    }

    private bool AddRecord(string record)
    {
      try
      {
        if (!System.IO.Directory.Exists(Directory()))
          System.IO.Directory.CreateDirectory(Directory());
        using (var sw = File.AppendText(PathNameFile()))
        {
          sw.Write(record + BlockSeparator);
        }

        return true;
      }
      catch (Exception ex)
      {
        Debug.Print(ex.Message);
        Debugger.Break();
      }

      return false;
    }
  }
}