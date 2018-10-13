using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using NetworkManager;
using static NetworkManager.Utility;
using static NetworkManager.Network;

namespace BlockchainManager
{
  public static class HookToNetwork
  {
    public static Network CurrentNetwork { get { return _CurrentNetwork; } }
    internal static Network _CurrentNetwork;
    internal static Dictionary<string, Network> HookedNetworks;
    /// <summary>
    /// The new blockchain instances will all be created on the selected network.
    /// Use this function to change the current network.
    /// By default, the current network will be the last initialized network.
    /// </summary>
    /// <param name="NetworkName">Select the network with this name</param>
    public static void ChooseCurrentNetwork(string NetworkName)
    {
      try
      {
        _CurrentNetwork = HookedNetworks[NetworkName];
      }
      catch (Exception)
      {
        throw new Exception("No network with this name has been initialized");
      }
    }


    /// <summary>
    /// This method initializes the network.
    /// You can join the network as a node, and contribute to decentralization, or hook yourself to the network as an external user.
    /// To create a node, set the MyAddress parameter with your web address.If MyAddress is not set then you are an external user.
    /// </summary>
    /// <param name="MyAddress">Your web address. If you do not want to create the node, omit this parameter</param>
    /// <param name="EntryPoints">The list of permanent access points nodes, to access the network. If null then the entry points will be those set in the NetworkManager.Setup</param>
    /// <param name="NetworkName">The name of the infrastructure. For tests we recommend using "testnet"</param>
    public static Network Initialize(string MyAddress = null, Dictionary<string, string> EntryPoints = null, string NetworkName = "testnet")
    {
      //#if DEBUG
      //      //NodeList = new Node[1] { new Node() { Server = "http://www.bitboxlab.com", MachineName = "ANDREA", PublicKey = "" } };
      //      NodeList = new Node[1] { new Node() { Server = "http://localhost:55007", MachineName = Environment.MachineName, PublicKey = "" } };
      //#else
      //        NodeList = new Node[1] { new Node() { Server = "http://www.bitboxlab.com", MachineName = "ANDREA", PublicKey = "" } };
      //#endif
      if (HookedNetworks.ContainsKey(NetworkName))
        throw new Exception("Node already hooked");
      try
      {
        Node[] Nodes = null;
        if (EntryPoints != null)
        {
          var NodeList = new List<Node>();
          foreach (var Entry in EntryPoints)
            NodeList.Add(new Node() { MachineName = Entry.Key, Address = Entry.Value });
          Nodes = NodeList.ToArray();
        }
        var Network = new Network(Nodes, NetworkName, MyAddress);
        SetNetwork(Network);
        HookedNetworks.Add(NetworkName, Network);
        _CurrentNetwork = Network;
        return Network;
      }
      catch (Exception)
      {
        return null;
      }
    }
    private static bool SetNetwork(Network Network)
    {
      Network.BufferManager.AddSyncDataAction(ActionSync, "DataVector");
      return Network.Protocol.AddOnReceivingObjectAction("VectorBlocks", Blockchain.GetVectorBlocks);
    }
    private static void ActionSync(string XmlObject, DateTime Timestamp)
    {
      if (Converter.XmlToObject(XmlObject, typeof(Blockchain.Block.DataVector), out object ObjDataVector))
      {
        var DataVector = (Blockchain.Block.DataVector)ObjDataVector;
        var Block = new Blockchain.Block(DataVector.Blockchain, DataVector.Data, Timestamp);
      }
    }


  }

  public class Blockchain
  {
    public Blockchain()
    {
      this.Network = HookToNetwork._CurrentNetwork;
    }
    public Blockchain(string[] PublicKeys, string Group, string Name, BlockchainType Type, BlockSynchronization SynchronizationType, bool AcceptBodySignature, int MaxBlockLenght = 2048, double DaysExpiredAfterInactivity = 30)
    {
      this.Network = HookToNetwork._CurrentNetwork;
      this.PublicKeys = PublicKeys;
      this.Group = Group;
      this.Name = Name;
      this.Type = Type;
      this.SynchronizationType = SynchronizationType;
      this.AcceptBodySignature = AcceptBodySignature;
      this.MaxBlockLenght = MaxBlockLenght;
      this.ExpiredAfterInactivity = TimeSpan.FromDays(DaysExpiredAfterInactivity);
    }
    public Blockchain(string Group, string Name, BlockchainType Type, BlockSynchronization SynchronizationType, bool AcceptBodySignature, int MaxBlockLenght = 2048, double DaysExpiredAfterInactivity = 30)
    {
      this.Network = HookToNetwork._CurrentNetwork;
      this.Group = Group;
      this.Name = Name;
      this.Type = Type;
      this.SynchronizationType = SynchronizationType;
      this.AcceptBodySignature = AcceptBodySignature;
      this.MaxBlockLenght = MaxBlockLenght;
      this.ExpiredAfterInactivity = TimeSpan.FromDays(DaysExpiredAfterInactivity);
    }
    private Network Network = null;
    public void Save()
    {
      if ((!System.IO.Directory.Exists(Directory())))
        System.IO.Directory.CreateDirectory(Directory());
      using (System.IO.FileStream Stream = new System.IO.FileStream(PathNameFile() + ".info", System.IO.FileMode.Create))
      {
        System.Xml.Serialization.XmlSerializer xml = new System.Xml.Serialization.XmlSerializer(this.GetType());
        System.Xml.Serialization.XmlSerializerNamespaces xmlns = new System.Xml.Serialization.XmlSerializerNamespaces();
        xmlns.Add(string.Empty, string.Empty);
        xml.Serialize(Stream, this, xmlns);
      }
    }

    public static Blockchain Load(string Group, string Name)
    {
      try
      {
        string File = PathNameFile(HookToNetwork.CurrentNetwork, Group, Name) + ".info";
        Blockchain Value;
        if (System.IO.File.Exists(File))
        {
          using (System.IO.FileStream Stream = new System.IO.FileStream(File, System.IO.FileMode.Open, System.IO.FileAccess.Read))
          {
            System.Xml.Serialization.XmlSerializer XML = new System.Xml.Serialization.XmlSerializer(typeof(Blockchain));
            Value = (Blockchain)XML.Deserialize(Stream);
          }
          return Value;
        }
      }
      catch (Exception ex)
      {
      }
      return null;
    }
    public bool AcceptBodySignature;
    public @TimeSpan ExpiredAfterInactivity;
    public string PublicKey
    {
      set { PublicKeys = new string[1] { value }; }
    }
    /// <summary>
    /// List of private key authorized to sign the block:
    /// If is not null then all block Checksum are signed with one of this private key  
    /// </summary>
    public string[] PublicKeys;
    public string Group;
    public string Name;
    /// <summary>
    /// How the blocks will be synchronized on the blockchain
    /// </summary>
    public BlockSynchronization SynchronizationType;
    /// <summary>
    /// If you use the AddInLocalAndSync mode, make sure that no blocks are added simultaneously.
    /// If you use SendToTheNetworkBuffer mode, the network will add blocks to the blockchain.
    /// </summary>
    public enum BlockSynchronization { AddInLocalAndSync, SendToTheNetworkBuffer }
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
      if (System.IO.File.Exists(this.PathNameFile()))
        return new System.IO.FileInfo(this.PathNameFile()).Length;
      else
        return 0;
    }
    public void Truncate(long Position)
    {
      using (System.IO.FileStream Stream = new System.IO.FileStream(this.PathNameFile(), System.IO.FileMode.Truncate))
      {
        Stream.SetLength(Position);
      }
    }
    internal static object GetVectorBlocks(string XmlVectorBlocks)
    {
      object Obj;
      object ReturnObject;
      Converter.XmlToObject(XmlVectorBlocks, typeof(Blockchain.VectorBlocks), out Obj);
      Blockchain.VectorBlocks VectorBlocks = (Blockchain.VectorBlocks)Obj;
      Blockchain.VectorBlocks ReturnVectorBlocks = new Blockchain.VectorBlocks();
      if (UpdateLocalBlockchain(VectorBlocks, ReturnVectorBlocks))
        ReturnObject = ReturnVectorBlocks;
      else
        ReturnObject = "error: blockchain corrupted";
      return ReturnObject;
    }

    /// <summary>
    /// This object is used to send or receive blocks
    /// To receive the blocks from the remote server, set the RequestSendBlocksFromPosition parameter
    /// The parameter Position indicates the position in the blockchain of the inserted vector blocks
    /// Position is base 0
    /// </summary>
    public class VectorBlocks
    {
      public VectorBlocks()
      {
      }
      public VectorBlocks(Blockchain Blockchain)
      {
        this.Blockchain = Blockchain;
      }
      public Blockchain Blockchain;
      public long Position = -1; //Base 0
      /// <summary>
      /// Ask to receive blocks from the Base 0 position, if this value is -1 then there is no request
      /// </summary>
      public long RequestSendBlocksFromPosition = -1;
      public ReadBlocksResult ReadBlocksResult;
      public List<Block> Blocks
      {
        set
        {
          List<string> List = new List<string>();
          foreach (var Block in value)
            List.Add(Block.Record);
          Records = List.ToArray();
        }
      }
      public string[] Records;
    }

    /// <summary>
    /// Synchronize the local blockchain, with the nodes remotely
    /// </summary>
    /// <returns>Returns False if the operation fails</returns>
    public bool RequestAnyNewBlocks()
    {
      return Network.InteractWithRandomNode((Node Node) =>
       {
         try
         {
           long CurrentLength = this.Length();
           VectorBlocks Vector = new VectorBlocks() { Blockchain = this, RequestSendBlocksFromPosition = CurrentLength };
           VectorToNode(Vector, Node.Address, Node.MachineName);
           return true;
         }
         catch (Exception)
         {
           return false;
         }
       });
    }
    private void VectorToNode(VectorBlocks Vector, string Server, string MachineName)
    {
      VectorBlocks ReturnVector;
      do
      {
        ReturnVector = null;
        string ReturnObjectName = null;
        string ReturnXmlObject = null;
        string ReturnFromUser = null;
        object Obj = null;
        var XmlObjectVector = Network.Comunication.SendObjectSync((object)Vector, Server, null, MachineName);
        if (!string.IsNullOrEmpty(XmlObjectVector))
        {
          object ReturmObj;
          Converter.XmlToObject(XmlObjectVector, typeof(ComunicationClass.ObjectVector), out ReturmObj);
          ComunicationClass.ObjectVector ObjVector = (ComunicationClass.ObjectVector)ReturmObj;
          ReturnObjectName = ObjVector.ObjectName;
          ReturnXmlObject = ObjVector.XmlObject;
          ReturnFromUser = ObjVector.FromUser;
          if (ReturnObjectName == "VectorBlocks")
          {
            Converter.XmlToObject(ReturnXmlObject, typeof(VectorBlocks), out Obj);
            ReturnVector = (VectorBlocks)Obj;
            if (ReturnVector.Blockchain == null)
              ReturnVector.Blockchain = Vector.Blockchain;
            if (ReturnVector.RequestSendBlocksFromPosition != -1)
            {
              var BlocksToSend = GetBlocks(ReturnVector.RequestSendBlocksFromPosition, out ReadBlocksResult ReadBlocksResult);
              VectorBlocks VectorToSend = new VectorBlocks() { Blockchain = this, Blocks = BlocksToSend, Position = ReturnVector.RequestSendBlocksFromPosition, ReadBlocksResult = ReadBlocksResult };
              VectorToNode(VectorToSend, Server, MachineName);
            }
            else
            {
              Vector = new VectorBlocks(); //Used to repeat the operation in case of partial reception of blocks
              UpdateLocalBlockchain(ReturnVector, Vector);
            }
          }
          else
          {
            ReturnObjectName = "String";
            Converter.XmlToObject(ReturnXmlObject, typeof(string), out Obj);
            string ErrorMessage = System.Convert.ToString(Obj);
            Log("BlockchainError", 1000, ErrorMessage);
          }
        }
      } while (ReturnVector != null && ReturnVector.ReadBlocksResult == ReadBlocksResult.Partial);
    }
    /// <summary>
    /// Send a locally block it to the nodes of the network
    /// </summary>
    /// <param name="Block">The block</param>
    /// <returns>Returns False if the operation fails</returns>
    public bool SendBlockToNetwork(Block Block)
    {
      return SyncBlocksToNetwork(new List<Block>() { Block }, -1);
    }
    /// <summary>
    /// Send locally blocks it to the nodes of the network
    /// </summary>
    /// <param name="Blocks">The blocks</param>
    /// <returns>Returns False if the operation fails</returns>
    public bool SendBlocksToNetwork(List<Block> Blocks)
    {
      return SyncBlocksToNetwork(Blocks, -1);
    }
    /// <summary>
    /// Synchronize a block written locally and transmit it to the nodes of the network
    /// </summary>
    /// <param name="Block">The block</param>
    /// <param name="Position">Base 0 position</param>
    /// <returns>Returns False if the operation fails</returns>
    public bool SyncBlockToNetwork(Block Block, long Position)
    {
      return SyncBlocksToNetwork(new List<Block>() { Block }, Position);
    }
    /// <summary>
    /// Synchronize the blocks written locally and transmit it to the nodes of the network
    /// </summary>
    /// <param name="Blocks">The blocks</param>
    /// <param name="Position">Base 0 position</param>
    /// <returns>Returns False if the operation fails</returns>
    public bool SyncBlocksToNetwork(List<Block> Blocks, long Position)
    {
      return Network.InteractWithRandomNode((Node Node) =>
       {
         try
         {
           VectorBlocks Vector = new VectorBlocks() { Blockchain = this, Blocks = Blocks, Position = Position };
           if (Node.MachineName != Network.MachineName)
             VectorToNode(Vector, Node.Address, Node.MachineName);
           return true;
         }
         catch (Exception)
         {
           return false;
         }
       });
    }

    /// <summary>
    /// Add to the local blockchain the blocks received from the server
    /// This function is normally called by the Page.Load event when a Vector is received remotely
    /// </summary>
    /// <param name="Vector">Parameter that is used to send blocks or to request blocks</param>
    /// <param name="SetReturnVector">This parameter returns a vector containing possible blocks to be synchronized on the local blockchain</param>
    /// <returns>Returns False if the operation fails</returns>
    public static bool UpdateLocalBlockchain(VectorBlocks Vector, VectorBlocks SetReturnVector = null)
    {

      Blockchain Blockchain = Vector.Blockchain;
      long CurrentLength = Blockchain.Length();
      if (CurrentLength == 0)
        Blockchain.Save();

      if (Vector.RequestSendBlocksFromPosition != -1 && SetReturnVector != null)
      {
        if (CurrentLength > Vector.RequestSendBlocksFromPosition)
        {
          SetReturnVector.Blockchain = Blockchain;
          SetReturnVector.Blocks = Blockchain.GetBlocks(Vector.RequestSendBlocksFromPosition, out SetReturnVector.ReadBlocksResult);
          SetReturnVector.Position = Vector.RequestSendBlocksFromPosition;
        }
        else if (CurrentLength < Vector.RequestSendBlocksFromPosition)
        {
          SetReturnVector.Blockchain = Blockchain;
          SetReturnVector.RequestSendBlocksFromPosition = CurrentLength;
          //qui non mi ricordo cosa stavo facendo, probabilmente devo continuare da qui
          //VectorToNode()
        }
      }
      else if (Vector.Position != -1)
      {
        if (CurrentLength > Vector.Position)
        {
          if (SetReturnVector != null)
          {
            SetReturnVector.Blockchain = Blockchain;
            SetReturnVector.Blocks = Blockchain.GetBlocks(Vector.Position, out SetReturnVector.ReadBlocksResult);
            SetReturnVector.Position = Vector.Position;
          }
          else
          {
            Blockchain.Truncate(Vector.Position);
            CurrentLength = Vector.Position;
          }
        }

        if (CurrentLength == Vector.Position)
        {
          foreach (String Record in Vector.Records)
          {
            if (!Blockchain.AddRecord(Record))
              // Error in blockchain
              return false;
          }
          if (Vector.ReadBlocksResult == ReadBlocksResult.Partial)
            //You have received only a partial part of blocks, you have to ask others who are missing
            if (SetReturnVector != null)
            {
              SetReturnVector.Blockchain = Blockchain;
              SetReturnVector.RequestSendBlocksFromPosition = Blockchain.Length();
            }
        }
        else if (CurrentLength < Vector.Position)
        {
          // Send a request of th missed blocks 
          if (SetReturnVector != null)
          {
            SetReturnVector.Blockchain = Blockchain;
            SetReturnVector.RequestSendBlocksFromPosition = CurrentLength;
          }
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
      /// Instantiate a block from a record of data written on the blockchain.
      /// It is used to read the blockchain.
      /// </summary>
      /// <param name="PreviousBlock">The previous block</param>
      /// <param name="Blockchain">The blockchain</param>
      /// <param name="Record">The record is the entire data package that represents the block, includes the possible signature and checksum</param>
      public Block(Block PreviousBlock, Blockchain Blockchain, string Record)
      {
        this.PreviousBlock = PreviousBlock;
        this.Blockchain = Blockchain;
        this.Record = Record;
      }
      /// <summary>
      /// Create a block that will be immediately added to the blockchain.
      /// If the blockchain has set a public key, then the block will not be added now, but will need to be added later once the signature is added
      /// </summary>
      /// <param name="Blockchain">The Blockchain used</param>
      /// <param name="Data">The data to be included in the block</param>
      public Block(Blockchain Blockchain, byte[] Data)
      {
        _Block(Blockchain, Convert.ToBase64String(Data));
      }
      /// <summary>
      /// Create a block that will be immediately added to the blockchain.
      /// If the blockchain has set a public key, then the block will not be added now, but will need to be added later once the signature is added
      /// </summary>
      /// <param name="Blockchain">The Blockchain used</param>
      /// <param name="Data">The data to be included in the block</param>
      public Block(Blockchain Blockchain, string Data)
      {
        switch (Blockchain.Type)
        {
          case BlockchainType.Xml:
            Data.Replace("\n", "").Replace("\r", "");
            break;
          case BlockchainType.Binary:
            throw new System.InvalidOperationException("Invalid method with the blockchain in binary mode");
        }
        _Block(Blockchain, Data);
      }

      /// <summary>
      /// Use this method only for data that exits from shared buffer
      /// </summary>
      /// <param name="Blockchain"></param>
      /// <param name="Data"></param>
      /// <param name="TimeStamp">The timestam assigned by the buffer</param>
      internal Block(Blockchain Blockchain, string Data, DateTime TimeStamp)
      {
        _Block(Blockchain, Data, Timestamp, true);
      }

      /// <summary>
      /// Set a block that will be immediately added to the blockchain.
      /// If the blockchain has set a public key, then the block will not be added now, but will need to be added later once the signature is added
      /// </summary>
      /// <param name="Blockchain">The Blockchain used</param>
      /// <param name="Data">The data to be included in the block</param>
      private void _Block(Blockchain Blockchain, string Data, DateTime TimeStamp = default(DateTime), bool Local = false)
      {
        this.Blockchain = Blockchain;
        this._Data = Data;
        if (TimeStamp != default(DateTime))
          _Timestamp = TimeStamp;
        else
          _Timestamp = DateTime.Now.ToUniversalTime();
        if (Local == true || Blockchain.SynchronizationType == BlockSynchronization.AddInLocalAndSync)
        {
          PreviousBlock = Blockchain.GetLastBlock();
          _Checksum = CalculateChecksum();
          if (!Blockchain.AcceptBodySignature)
          {
            if (Blockchain.PublicKeys == null)
              AddToBlockchain();
          }
        }
        else
        {
          DataVector Vector = new DataVector();
          Blockchain.Network.BufferManager.AddToSaredBuffer(Vector);
          //Blockchain.SendBlockToNetwork(this);
        }
      }
      /// <summary>
      /// This element is used to send the data inserted in the block to the shared buffer
      /// </summary>
      public class DataVector
      {
        public Blockchain Blockchain;
        public String Data;
      }
      private Block PreviousBlock;
      public bool AddBlockSignature(byte[] SignedChecksum)
      {
        _Checksum = Convert.ToBase64String(SignedChecksum);
        bool Result = CheckBlockSignature();
        if (Result)
          AddToBlockchain();
        return Result;
      }
      public bool CheckBlockSignature()
      {
        try
        {
          foreach (var PublicKey in Blockchain.PublicKeys)
          {
            System.Security.Cryptography.RSACryptoServiceProvider RSAalg = new System.Security.Cryptography.RSACryptoServiceProvider();
            RSAalg.ImportCspBlob(Convert.FromBase64String(PublicKey));
            if (RSAalg.VerifyHash(CalculateChecksumBytes(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"), ChecksumBytes)) ;
            return true;
          }
          return false;
        }
        catch (Exception e)
        {
          Console.WriteLine(e.Message);
          return false;
        }
      }
      private byte[] BaseChecksum()
      {
        string PreviousChecksum = null;
        if (PreviousBlock != null)
          PreviousChecksum = PreviousBlock.Checksum;
        string BaseComputation = BodyRecord(true);
        return Encoding.Unicode.GetBytes(PreviousChecksum + BaseComputation);
      }
      public byte[] CalculateChecksumBytes()
      {
        System.Security.Cryptography.HashAlgorithm hashType = new System.Security.Cryptography.SHA256Managed();
        byte[] hashBytes = hashType.ComputeHash(BaseChecksum());
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
          if (Blockchain.PublicKeys != null)
            return CheckBlockSignature();
          else
            return _Checksum == CalculateChecksum();
        }
        return false;
      }
      private Blockchain Blockchain;
      public bool AddToBlockchain(Blockchain Blockchain = null)
      {
        if (this.Blockchain == null)
          this.Blockchain = Blockchain;
        return this.Blockchain.AddBlock(this);
      }
      internal bool AddedToBlockchain;
      private string _Data;
      public string Data
      {
        get
        {
          if (Blockchain.Type == BlockchainType.Binary)
            throw new System.InvalidOperationException("Invalid method with the blockchain in binary mode");
          return _Data;
        }
      }
      public byte[] DataByteArray
      {
        get
        {
          if (Blockchain.Type != BlockchainType.Binary)
            throw new System.InvalidOperationException("Invalid method with the blockchain is not in binary mode");
          return Convert.FromBase64String(_Data);
        }
      }
      private DateTime _Timestamp;
      public DateTime Timestamp
      {
        get
        {
          return _Timestamp;
        }
      }
      private string _Checksum;
      public string Checksum
      {
        get
        {
          return _Checksum;
        }
      }
      public byte[] ChecksumBytes
      {
        get
        {
          return Convert.FromBase64String(_Checksum);
        }
      }
      private string _BodySignatures;
      /// <summary>
      /// Returns a dictionary indexed with public keys, and the values of the block signatures
      /// </summary>
      /// <returns></returns>
      public Dictionary<string, string> GetAllBodySignature()
      {
        Dictionary<string, string> Result = null;
        if (!string.IsNullOrEmpty(_BodySignatures))
        {
          Result = new Dictionary<string, string>();
          string[] Parts = _BodySignatures.Split(' ');
          string PublicKey = null;
          string Signature;
          bool Flag = false;
          foreach (string Part in Parts)
          {
            if (Flag)
            {
              Signature = Part;
              Result.Add(PublicKey, Signature);
            }
            else
              PublicKey = Part;
            Flag = !Flag;
          }
        }
        return Result;
      }
      public bool AddBodySignature(string PublicKey, byte[] Signature, bool AddNowToBlockchain)
      {
        if (Blockchain.AcceptBodySignature)
        {
          if (CheckBodySignature(PublicKey, Signature))
          {
            if (!string.IsNullOrEmpty(_BodySignatures))
              _BodySignatures += " ";
            _BodySignatures += PublicKey + " " + Convert.ToBase64String(Signature);
            _Checksum = CalculateChecksum();
            if (AddNowToBlockchain)
              return this.AddToBlockchain();
            return true;
          }
        }
        else
          throw new System.Exception("This blockchain does not allow to add signatures to the body");
        return false;
      }
      public bool CheckBodySignatures()
      {
        Dictionary<string, string> Signatures = GetAllBodySignature();
        if (Signatures != null)
        {
          foreach (string PubKey in Signatures.Keys)
          {
            if (!CheckBodySignature(PubKey, Convert.FromBase64String(Signatures[PubKey])))
              return false;
          }
        }
        return true;
      }
      private bool CheckBodySignature(string PublicKey, byte[] Signature)
      {
        try
        {
          System.Security.Cryptography.RSACryptoServiceProvider RSAalg = new System.Security.Cryptography.RSACryptoServiceProvider();
          RSAalg.ImportCspBlob(Convert.FromBase64String(PublicKey));
          return RSAalg.VerifyHash(HashBody(), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"), Signature);
        }
        catch (Exception e)
        {
          Console.WriteLine(e.Message);
          return false;
        }
      }
      public byte[] HashBody()
      {
        System.Security.Cryptography.HashAlgorithm hashType = new System.Security.Cryptography.SHA256Managed();
        byte[] hashBytes = hashType.ComputeHash(Encoding.Unicode.GetBytes(BodyRecord(false)));
        return hashBytes;
      }
      private string BodyRecord(bool WithSigatures)
      {
        var HexTimestamp = _Timestamp.Ticks.ToString("X");
        string Signatures = null;
        if (WithSigatures)
        {
          if (!string.IsNullOrEmpty(_BodySignatures))
            Signatures = Blockchain.FieldsSeparator + _BodySignatures;
        }
        return _Data + Blockchain.FieldsSeparator + HexTimestamp + Signatures;
      }
      protected internal string Record
      {
        get
        {
          return BodyRecord(true) + Blockchain.FieldsSeparator + _Checksum;
        }
        set
        {
          if (!string.IsNullOrEmpty(value))
          {
            // ===========PARTS==========================
            // Data + Timestamp + (Signatures) + Checksum
            // ==========================================
            string[] Parts = value.Split(new string[] { Blockchain.FieldsSeparator }, StringSplitOptions.None);
            //if (Blockchain.Type != BlockchainType.LineOfText)
            //  _Data = Converter.Base64ToString(Parts[0]);
            //else
            _Data = Parts[0];
            string DateHex = Parts[1];
            _Timestamp = new DateTime(Convert.ToInt64(DateHex, 16));
            if (Parts.Count() == 4)
              _BodySignatures = Parts[2];
            _Checksum = Parts.Last();
          }
        }
      }
    }
    private static string MapPath(string PathNameFile)
    {
      //return System.IO.Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.ApplicationData), PathNameFile);
      string Path = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
      return System.IO.Path.Combine(Path, PathNameFile);

    }
    private static string Directory(Network Network, string Group)
    {
      return MapPath(System.IO.Path.Combine(Setup.Ambient.Repository, AbjustNameFile(Network.NetworkName), AbjustNameFile(Group)));
    }
    private string Directory()
    {
      return Directory(Network, Group);
    }
    private static string PathNameFile(Network Network, string Group, string Name)
    {
      return System.IO.Path.Combine(Directory(Network, Group), AbjustNameFile(Name) + ".bloks");
    }
    private string PathNameFile()
    {
      return System.IO.Path.Combine(Directory(), AbjustNameFile(Name) + ".bloks");
    }
    private static string AbjustNameFile(string FileName)
    {
      string Result = "";
      foreach (char c in FileName)
      {
        if (char.IsLetterOrDigit(c) || "+-=._".Contains(c))
          Result += c;
        else
        {
          Result += "(" + String.Format("{0:X}", Convert.ToInt32(c)) + ")";
        }
      }
      return Result;
    }
    public Block GetLastBlock()
    {
      return GetPreviousBlock(-1);
    }
    /// <summary>
    /// Returns the block preceding the position on file Position, the parameter Position is base 0
    /// </summary>
    /// <param name="Position">File position base 0, if Position is -1 then return the last block in blockchain</param>
    /// <returns></returns>
    public Block GetPreviousBlock(long Position)
    {
      Block Output = null;
      string File = PathNameFile();
      if (System.IO.File.Exists(File))
      {
        string Data = null;
        System.IO.StreamReader Stream = null;
        int NTryError = 0;
        try
        {
          Stream = new System.IO.StreamReader(File);
          if (Position == -1)
            Position = Stream.BaseStream.Length;
          long StartRead = Position - (long)MaxBlockLenght;
          if (StartRead < 0)
            StartRead = 0;
          Stream.BaseStream.Position = StartRead;

          int Len = (int)(Position - StartRead);
          char[] Buffer = new char[Len];
          Len = Stream.Read(Buffer, 0, Len);
          Data = new string(Buffer);
        }
        catch (Exception ex)
        {
          NTryError += 1;
          System.Threading.Thread.Sleep(500);
        }
        finally
        {
          if (Stream != null)
          {
            Stream.Close();
            Stream.Dispose();
          }
        }
        if (!string.IsNullOrEmpty(Data))
        {
          string[] Blocks = Data.Split(new string[] { BlockSeparator }, StringSplitOptions.None);
          string Block = Blocks[Blocks.Count() - 2];
          Output = new Block(null, this, Block);
        }
      }
      return Output;
    }

    public int Validate()
    {
      // Return 0 = No error, else return the block number with error
      Block LastBlock = null;
      int InvalidBlock = 0;
      if (System.IO.File.Exists(PathNameFile()))
      {
        using (System.IO.StreamReader Stream = System.IO.File.OpenText(PathNameFile()))
        {
          int N = 0;
          while (!Stream.EndOfStream)
          {
            N += 1;
            string Record = Stream.ReadLine();
            Block Block = new Block(LastBlock, this, Record);
            if (!Block.IsValid())
            {
              InvalidBlock = N;
              break;
            }
            LastBlock = Block;
          }
        }
      }
      return InvalidBlock;
    }
    public List<Block> GetBlocks(long FromPosition, out ReadBlocksResult Feedback)
    {
      var Blocks = new List<Block>();
      Action<Block> Execute = delegate (Block Block)
      {
        Blocks.Add(Block);
      };
      Feedback = ReadBlocks(FromPosition, Execute, LenghtDataTrasmission);
      return Blocks;
    }

    public ReadBlocksResult ReadBlocks(long FromPosition, Action<Block> Execute, long ExitAtLengthData = 0)
    {
      //List<Block> List = new List<Block>();
      long LengthData = 0;
      Block LastBlock = GetPreviousBlock(FromPosition);
      if (System.IO.File.Exists(PathNameFile()))
      {
        using (System.IO.StreamReader Stream = System.IO.File.OpenText(PathNameFile()))
        {
          Stream.BaseStream.Position = FromPosition;
          while (!Stream.EndOfStream)
          {
            string Record = Stream.ReadLine();
            LengthData += Record.Length;
            Block Block = new Block(LastBlock, this, Record);
            if (!Block.IsValid())
              // Blockchain error!
              return ReadBlocksResult.Error;
            //List.Add(Block);
            Execute(Block);
            if (ExitAtLengthData != 0)
              if (LengthData >= ExitAtLengthData)
              {
                return ReadBlocksResult.Partial;
              }
            LastBlock = Block;
          }
        }
      }
      return ReadBlocksResult.Completed;
      //return List;
    }
    public enum ReadBlocksResult { Completed, Partial, Error }
    private bool AddBlock(Block Block)
    {
      if (Block.AddedToBlockchain)
        throw new System.InvalidOperationException("The block has already been added to the blockchain");
      if (AddRecord(Block.Record))
      {
        Block.AddedToBlockchain = true;
        return true;
      }
      return false;
    }
    private bool AddRecord(string Record)
    {
      try
      {
        if ((!System.IO.Directory.Exists(Directory())))
          System.IO.Directory.CreateDirectory(Directory());
        using (System.IO.StreamWriter sw = System.IO.File.AppendText(PathNameFile()))
        {
          sw.Write(Record + BlockSeparator);
        }
        return true;
      }
      catch (Exception ex)
      {
        return false;
      }
    }
  }
}

