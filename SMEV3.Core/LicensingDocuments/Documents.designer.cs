// ------------------------------------------------------------------------------
//  <auto-generated>
//    Generated by Xsd2Code. Version 3.4.0.32989
//    <NameSpace>SMEV3.LicensingDocuments</NameSpace><Collection>List</Collection><codeType>CSharp</codeType><EnableDataBinding>False</EnableDataBinding><EnableLazyLoading>False</EnableLazyLoading><TrackingChangesEnable>False</TrackingChangesEnable><GenTrackingClasses>False</GenTrackingClasses><HidePrivateFieldInIDE>False</HidePrivateFieldInIDE><EnableSummaryComment>False</EnableSummaryComment><VirtualProp>False</VirtualProp><IncludeSerializeMethod>True</IncludeSerializeMethod><UseBaseClass>False</UseBaseClass><GenBaseClass>False</GenBaseClass><GenerateCloneMethod>False</GenerateCloneMethod><GenerateDataContracts>False</GenerateDataContracts><CodeBaseTag>Net40</CodeBaseTag><SerializeMethodName>Serialize</SerializeMethodName><DeserializeMethodName>Deserialize</DeserializeMethodName><SaveToFileMethodName>SaveToFile</SaveToFileMethodName><LoadFromFileMethodName>LoadFromFile</LoadFromFileMethodName><GenerateXMLAttributes>True</GenerateXMLAttributes><OrderXMLAttrib>False</OrderXMLAttrib><EnableEncoding>False</EnableEncoding><AutomaticProperties>False</AutomaticProperties><GenerateShouldSerialize>False</GenerateShouldSerialize><DisableDebug>False</DisableDebug><PropNameSpecified>Default</PropNameSpecified><Encoder>UTF8</Encoder><CustomUsings></CustomUsings><ExcludeIncludedTypes>False</ExcludeIncludedTypes><EnableInitializeFields>True</EnableInitializeFields>
//  </auto-generated>
// ------------------------------------------------------------------------------
namespace SMEV3.LicensingDocuments
{
	using System;
	using System.Diagnostics;
	using System.Xml.Serialization;
	using System.Collections;
	using System.Xml.Schema;
	using System.ComponentModel;
	using System.IO;
	using System.Text;
	using System.Collections.Generic;


	[System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.7.2612.0")]
	[System.SerializableAttribute()]
	[System.ComponentModel.DesignerCategoryAttribute("code")]
	[System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "http://www.minprom.gov.ru/schemas/licensing/Documents/1.0.0")]
	[System.Xml.Serialization.XmlRootAttribute(Namespace = "http://www.minprom.gov.ru/schemas/licensing/Documents/1.0.0", IsNullable = false)]
	public partial class DocumentsRequest
	{

		private System.DateTime startDateField;

		private System.DateTime endDateField;

		private bool endDateFieldSpecified;

		private static System.Xml.Serialization.XmlSerializer serializer;

		[System.Xml.Serialization.XmlElementAttribute(DataType = "date")]
		public System.DateTime StartDate
		{
			get
			{
				return this.startDateField;
			}
			set
			{
				this.startDateField = value;
			}
		}

		[System.Xml.Serialization.XmlElementAttribute(DataType = "date")]
		public System.DateTime EndDate
		{
			get
			{
				return this.endDateField;
			}
			set
			{
				this.endDateField = value;
			}
		}

		[System.Xml.Serialization.XmlIgnoreAttribute()]
		public bool EndDateSpecified
		{
			get
			{
				return this.endDateFieldSpecified;
			}
			set
			{
				this.endDateFieldSpecified = value;
			}
		}

		private static System.Xml.Serialization.XmlSerializer Serializer
		{
			get
			{
				if ((serializer == null))
				{
					serializer = new System.Xml.Serialization.XmlSerializer(typeof(DocumentsRequest));
				}
				return serializer;
			}
		}

		#region Serialize/Deserialize
		/// <summary>
		/// Serializes current DocumentsRequest object into an XML document
		/// </summary>
		/// <returns>string XML value</returns>
		public virtual string Serialize()
		{
			System.IO.StreamReader streamReader = null;
			System.IO.MemoryStream memoryStream = null;
			try
			{
				memoryStream = new System.IO.MemoryStream();
				Serializer.Serialize(memoryStream, this);
				memoryStream.Seek(0, System.IO.SeekOrigin.Begin);
				streamReader = new System.IO.StreamReader(memoryStream);
				return streamReader.ReadToEnd();
			}
			finally
			{
				if ((streamReader != null))
				{
					streamReader.Dispose();
				}
				if ((memoryStream != null))
				{
					memoryStream.Dispose();
				}
			}
		}

		/// <summary>
		/// Deserializes workflow markup into an DocumentsRequest object
		/// </summary>
		/// <param name="xml">string workflow markup to deserialize</param>
		/// <param name="obj">Output DocumentsRequest object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool Deserialize(string xml, out DocumentsRequest obj, out System.Exception exception)
		{
			exception = null;
			obj = default(DocumentsRequest);
			try
			{
				obj = Deserialize(xml);
				return true;
			}
			catch (System.Exception ex)
			{
				exception = ex;
				return false;
			}
		}

		public static bool Deserialize(string xml, out DocumentsRequest obj)
		{
			System.Exception exception = null;
			return Deserialize(xml, out obj, out exception);
		}

		public static DocumentsRequest Deserialize(string xml)
		{
			System.IO.StringReader stringReader = null;
			try
			{
				stringReader = new System.IO.StringReader(xml);
				return ((DocumentsRequest)(Serializer.Deserialize(System.Xml.XmlReader.Create(stringReader))));
			}
			finally
			{
				if ((stringReader != null))
				{
					stringReader.Dispose();
				}
			}
		}

		/// <summary>
		/// Serializes current DocumentsRequest object into file
		/// </summary>
		/// <param name="fileName">full path of outupt xml file</param>
		/// <param name="exception">output Exception value if failed</param>
		/// <returns>true if can serialize and save into file; otherwise, false</returns>
		public virtual bool SaveToFile(string fileName, out System.Exception exception)
		{
			exception = null;
			try
			{
				SaveToFile(fileName);
				return true;
			}
			catch (System.Exception e)
			{
				exception = e;
				return false;
			}
		}

		public virtual void SaveToFile(string fileName)
		{
			System.IO.StreamWriter streamWriter = null;
			try
			{
				string xmlString = Serialize();
				System.IO.FileInfo xmlFile = new System.IO.FileInfo(fileName);
				streamWriter = xmlFile.CreateText();
				streamWriter.WriteLine(xmlString);
				streamWriter.Close();
			}
			finally
			{
				if ((streamWriter != null))
				{
					streamWriter.Dispose();
				}
			}
		}

		/// <summary>
		/// Deserializes xml markup from file into an DocumentsRequest object
		/// </summary>
		/// <param name="fileName">string xml file to load and deserialize</param>
		/// <param name="obj">Output DocumentsRequest object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool LoadFromFile(string fileName, out DocumentsRequest obj, out System.Exception exception)
		{
			exception = null;
			obj = default(DocumentsRequest);
			try
			{
				obj = LoadFromFile(fileName);
				return true;
			}
			catch (System.Exception ex)
			{
				exception = ex;
				return false;
			}
		}

		public static bool LoadFromFile(string fileName, out DocumentsRequest obj)
		{
			System.Exception exception = null;
			return LoadFromFile(fileName, out obj, out exception);
		}

		public static DocumentsRequest LoadFromFile(string fileName)
		{
			System.IO.FileStream file = null;
			System.IO.StreamReader sr = null;
			try
			{
				file = new System.IO.FileStream(fileName, FileMode.Open, FileAccess.Read);
				sr = new System.IO.StreamReader(file);
				string xmlString = sr.ReadToEnd();
				sr.Close();
				file.Close();
				return Deserialize(xmlString);
			}
			finally
			{
				if ((file != null))
				{
					file.Dispose();
				}
				if ((sr != null))
				{
					sr.Dispose();
				}
			}
		}
		#endregion
	}

	[System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.7.2612.0")]
	[System.SerializableAttribute()]
	[System.ComponentModel.DesignerCategoryAttribute("code")]
	[System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "http://www.minprom.gov.ru/schemas/licensing/Documents/1.0.0")]
	[System.Xml.Serialization.XmlRootAttribute(Namespace = "http://www.minprom.gov.ru/schemas/licensing/Documents/1.0.0", IsNullable = false)]
	public partial class DocumentsResponse
	{

		private List<DocumentsResponseDocument> documentField;

		private static System.Xml.Serialization.XmlSerializer serializer;

		public DocumentsResponse()
		{
			this.documentField = new List<DocumentsResponseDocument>();
		}

		[System.Xml.Serialization.XmlElementAttribute("Document")]
		public List<DocumentsResponseDocument> Document
		{
			get
			{
				return this.documentField;
			}
			set
			{
				this.documentField = value;
			}
		}

		private static System.Xml.Serialization.XmlSerializer Serializer
		{
			get
			{
				if ((serializer == null))
				{
					serializer = new System.Xml.Serialization.XmlSerializer(typeof(DocumentsResponse));
				}
				return serializer;
			}
		}

		#region Serialize/Deserialize
		/// <summary>
		/// Serializes current DocumentsResponse object into an XML document
		/// </summary>
		/// <returns>string XML value</returns>
		public virtual string Serialize()
		{
			System.IO.StreamReader streamReader = null;
			System.IO.MemoryStream memoryStream = null;
			try
			{
				memoryStream = new System.IO.MemoryStream();
				Serializer.Serialize(memoryStream, this);
				memoryStream.Seek(0, System.IO.SeekOrigin.Begin);
				streamReader = new System.IO.StreamReader(memoryStream);
				return streamReader.ReadToEnd();
			}
			finally
			{
				if ((streamReader != null))
				{
					streamReader.Dispose();
				}
				if ((memoryStream != null))
				{
					memoryStream.Dispose();
				}
			}
		}

		/// <summary>
		/// Deserializes workflow markup into an DocumentsResponse object
		/// </summary>
		/// <param name="xml">string workflow markup to deserialize</param>
		/// <param name="obj">Output DocumentsResponse object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool Deserialize(string xml, out DocumentsResponse obj, out System.Exception exception)
		{
			exception = null;
			obj = default(DocumentsResponse);
			try
			{
				obj = Deserialize(xml);
				return true;
			}
			catch (System.Exception ex)
			{
				exception = ex;
				return false;
			}
		}

		public static bool Deserialize(string xml, out DocumentsResponse obj)
		{
			System.Exception exception = null;
			return Deserialize(xml, out obj, out exception);
		}

		public static DocumentsResponse Deserialize(string xml)
		{
			System.IO.StringReader stringReader = null;
			try
			{
				stringReader = new System.IO.StringReader(xml);
				return ((DocumentsResponse)(Serializer.Deserialize(System.Xml.XmlReader.Create(stringReader))));
			}
			finally
			{
				if ((stringReader != null))
				{
					stringReader.Dispose();
				}
			}
		}

		/// <summary>
		/// Serializes current DocumentsResponse object into file
		/// </summary>
		/// <param name="fileName">full path of outupt xml file</param>
		/// <param name="exception">output Exception value if failed</param>
		/// <returns>true if can serialize and save into file; otherwise, false</returns>
		public virtual bool SaveToFile(string fileName, out System.Exception exception)
		{
			exception = null;
			try
			{
				SaveToFile(fileName);
				return true;
			}
			catch (System.Exception e)
			{
				exception = e;
				return false;
			}
		}

		public virtual void SaveToFile(string fileName)
		{
			System.IO.StreamWriter streamWriter = null;
			try
			{
				string xmlString = Serialize();
				System.IO.FileInfo xmlFile = new System.IO.FileInfo(fileName);
				streamWriter = xmlFile.CreateText();
				streamWriter.WriteLine(xmlString);
				streamWriter.Close();
			}
			finally
			{
				if ((streamWriter != null))
				{
					streamWriter.Dispose();
				}
			}
		}

		/// <summary>
		/// Deserializes xml markup from file into an DocumentsResponse object
		/// </summary>
		/// <param name="fileName">string xml file to load and deserialize</param>
		/// <param name="obj">Output DocumentsResponse object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool LoadFromFile(string fileName, out DocumentsResponse obj, out System.Exception exception)
		{
			exception = null;
			obj = default(DocumentsResponse);
			try
			{
				obj = LoadFromFile(fileName);
				return true;
			}
			catch (System.Exception ex)
			{
				exception = ex;
				return false;
			}
		}

		public static bool LoadFromFile(string fileName, out DocumentsResponse obj)
		{
			System.Exception exception = null;
			return LoadFromFile(fileName, out obj, out exception);
		}

		public static DocumentsResponse LoadFromFile(string fileName)
		{
			System.IO.FileStream file = null;
			System.IO.StreamReader sr = null;
			try
			{
				file = new System.IO.FileStream(fileName, FileMode.Open, FileAccess.Read);
				sr = new System.IO.StreamReader(file);
				string xmlString = sr.ReadToEnd();
				sr.Close();
				file.Close();
				return Deserialize(xmlString);
			}
			finally
			{
				if ((file != null))
				{
					file.Dispose();
				}
				if ((sr != null))
				{
					sr.Dispose();
				}
			}
		}
		#endregion
	}

	[System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.7.2612.0")]
	[System.SerializableAttribute()]
	[System.ComponentModel.DesignerCategoryAttribute("code")]
	[System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "http://www.minprom.gov.ru/schemas/licensing/Documents/1.0.0")]
	public partial class DocumentsResponseDocument
	{

		private string regNumberField;

		private System.DateTime formDateField;

		private System.DateTime beginDateField;

		private System.DateTime endDateField;

		private bool endDateFieldSpecified;

		private DocumentsResponseDocumentDirection directionField;

		private System.DateTime contractDateField;

		private bool contractDateFieldSpecified;

		private string contractNumberField;

		private string contractorCountryCodeField;

		private string countractorCountryNamrField;

		private string agreementCodeField;

		private string customsCodeField;

		private string customsNameField;

		private string senderNameField;

		private string senderAddressField;

		private string senderInfoField;

		private string receiverNameField;

		private string receiverAddressField;

		private string receiverInfoField;

		private int commodityPositionField;

		private bool commodityPositionFieldSpecified;

		private string commodityNameField;

		private string commodityCodeField;

		private decimal quantityField;

		private bool quantityFieldSpecified;

		private decimal addQuantityField;

		private bool addQuantityFieldSpecified;

		private string addMeasureCodeField;

		private string responsibleFIOField;

		private string responsiblePostField;

		private DocumentsResponseDocumentConfirmationStatus confirmationStatusField;

		private System.DateTime confirmationAnnulDateField;

		private bool confirmationAnnulDateFieldSpecified;

		private System.DateTime lastModifiedDateField;

		private DocumentsResponseDocumentDocumentType documentTypeField;

		private static System.Xml.Serialization.XmlSerializer serializer;

		public string RegNumber
		{
			get
			{
				return this.regNumberField;
			}
			set
			{
				this.regNumberField = value;
			}
		}

		[System.Xml.Serialization.XmlElementAttribute(DataType = "date")]
		public System.DateTime FormDate
		{
			get
			{
				return this.formDateField;
			}
			set
			{
				this.formDateField = value;
			}
		}

		[System.Xml.Serialization.XmlElementAttribute(DataType = "date")]
		public System.DateTime BeginDate
		{
			get
			{
				return this.beginDateField;
			}
			set
			{
				this.beginDateField = value;
			}
		}

		[System.Xml.Serialization.XmlElementAttribute(DataType = "date")]
		public System.DateTime EndDate
		{
			get
			{
				return this.endDateField;
			}
			set
			{
				this.endDateField = value;
			}
		}

		[System.Xml.Serialization.XmlIgnoreAttribute()]
		public bool EndDateSpecified
		{
			get
			{
				return this.endDateFieldSpecified;
			}
			set
			{
				this.endDateFieldSpecified = value;
			}
		}

		public DocumentsResponseDocumentDirection Direction
		{
			get
			{
				return this.directionField;
			}
			set
			{
				this.directionField = value;
			}
		}

		[System.Xml.Serialization.XmlElementAttribute(DataType = "date")]
		public System.DateTime ContractDate
		{
			get
			{
				return this.contractDateField;
			}
			set
			{
				this.contractDateField = value;
			}
		}

		[System.Xml.Serialization.XmlIgnoreAttribute()]
		public bool ContractDateSpecified
		{
			get
			{
				return this.contractDateFieldSpecified;
			}
			set
			{
				this.contractDateFieldSpecified = value;
			}
		}

		public string ContractNumber
		{
			get
			{
				return this.contractNumberField;
			}
			set
			{
				this.contractNumberField = value;
			}
		}

		public string ContractorCountryCode
		{
			get
			{
				return this.contractorCountryCodeField;
			}
			set
			{
				this.contractorCountryCodeField = value;
			}
		}

		public string CountractorCountryNamr
		{
			get
			{
				return this.countractorCountryNamrField;
			}
			set
			{
				this.countractorCountryNamrField = value;
			}
		}

		public string AgreementCode
		{
			get
			{
				return this.agreementCodeField;
			}
			set
			{
				this.agreementCodeField = value;
			}
		}

		public string CustomsCode
		{
			get
			{
				return this.customsCodeField;
			}
			set
			{
				this.customsCodeField = value;
			}
		}

		public string CustomsName
		{
			get
			{
				return this.customsNameField;
			}
			set
			{
				this.customsNameField = value;
			}
		}

		public string SenderName
		{
			get
			{
				return this.senderNameField;
			}
			set
			{
				this.senderNameField = value;
			}
		}

		public string SenderAddress
		{
			get
			{
				return this.senderAddressField;
			}
			set
			{
				this.senderAddressField = value;
			}
		}

		public string SenderInfo
		{
			get
			{
				return this.senderInfoField;
			}
			set
			{
				this.senderInfoField = value;
			}
		}

		public string ReceiverName
		{
			get
			{
				return this.receiverNameField;
			}
			set
			{
				this.receiverNameField = value;
			}
		}

		public string ReceiverAddress
		{
			get
			{
				return this.receiverAddressField;
			}
			set
			{
				this.receiverAddressField = value;
			}
		}

		public string ReceiverInfo
		{
			get
			{
				return this.receiverInfoField;
			}
			set
			{
				this.receiverInfoField = value;
			}
		}

		public int CommodityPosition
		{
			get
			{
				return this.commodityPositionField;
			}
			set
			{
				this.commodityPositionField = value;
			}
		}

		[System.Xml.Serialization.XmlIgnoreAttribute()]
		public bool CommodityPositionSpecified
		{
			get
			{
				return this.commodityPositionFieldSpecified;
			}
			set
			{
				this.commodityPositionFieldSpecified = value;
			}
		}

		public string CommodityName
		{
			get
			{
				return this.commodityNameField;
			}
			set
			{
				this.commodityNameField = value;
			}
		}

		public string CommodityCode
		{
			get
			{
				return this.commodityCodeField;
			}
			set
			{
				this.commodityCodeField = value;
			}
		}

		public decimal Quantity
		{
			get
			{
				return this.quantityField;
			}
			set
			{
				this.quantityField = value;
			}
		}

		[System.Xml.Serialization.XmlIgnoreAttribute()]
		public bool QuantitySpecified
		{
			get
			{
				return this.quantityFieldSpecified;
			}
			set
			{
				this.quantityFieldSpecified = value;
			}
		}

		public decimal AddQuantity
		{
			get
			{
				return this.addQuantityField;
			}
			set
			{
				this.addQuantityField = value;
			}
		}

		[System.Xml.Serialization.XmlIgnoreAttribute()]
		public bool AddQuantitySpecified
		{
			get
			{
				return this.addQuantityFieldSpecified;
			}
			set
			{
				this.addQuantityFieldSpecified = value;
			}
		}

		public string AddMeasureCode
		{
			get
			{
				return this.addMeasureCodeField;
			}
			set
			{
				this.addMeasureCodeField = value;
			}
		}

		public string ResponsibleFIO
		{
			get
			{
				return this.responsibleFIOField;
			}
			set
			{
				this.responsibleFIOField = value;
			}
		}

		public string ResponsiblePost
		{
			get
			{
				return this.responsiblePostField;
			}
			set
			{
				this.responsiblePostField = value;
			}
		}

		public DocumentsResponseDocumentConfirmationStatus ConfirmationStatus
		{
			get
			{
				return this.confirmationStatusField;
			}
			set
			{
				this.confirmationStatusField = value;
			}
		}

		[System.Xml.Serialization.XmlElementAttribute(DataType = "date")]
		public System.DateTime ConfirmationAnnulDate
		{
			get
			{
				return this.confirmationAnnulDateField;
			}
			set
			{
				this.confirmationAnnulDateField = value;
			}
		}

		[System.Xml.Serialization.XmlIgnoreAttribute()]
		public bool ConfirmationAnnulDateSpecified
		{
			get
			{
				return this.confirmationAnnulDateFieldSpecified;
			}
			set
			{
				this.confirmationAnnulDateFieldSpecified = value;
			}
		}

		public System.DateTime LastModifiedDate
		{
			get
			{
				return this.lastModifiedDateField;
			}
			set
			{
				this.lastModifiedDateField = value;
			}
		}

		public DocumentsResponseDocumentDocumentType DocumentType
		{
			get
			{
				return this.documentTypeField;
			}
			set
			{
				this.documentTypeField = value;
			}
		}

		private static System.Xml.Serialization.XmlSerializer Serializer
		{
			get
			{
				if ((serializer == null))
				{
					serializer = new System.Xml.Serialization.XmlSerializer(typeof(DocumentsResponseDocument));
				}
				return serializer;
			}
		}

		#region Serialize/Deserialize
		/// <summary>
		/// Serializes current DocumentsResponseDocument object into an XML document
		/// </summary>
		/// <returns>string XML value</returns>
		public virtual string Serialize()
		{
			System.IO.StreamReader streamReader = null;
			System.IO.MemoryStream memoryStream = null;
			try
			{
				memoryStream = new System.IO.MemoryStream();
				Serializer.Serialize(memoryStream, this);
				memoryStream.Seek(0, System.IO.SeekOrigin.Begin);
				streamReader = new System.IO.StreamReader(memoryStream);
				return streamReader.ReadToEnd();
			}
			finally
			{
				if ((streamReader != null))
				{
					streamReader.Dispose();
				}
				if ((memoryStream != null))
				{
					memoryStream.Dispose();
				}
			}
		}

		/// <summary>
		/// Deserializes workflow markup into an DocumentsResponseDocument object
		/// </summary>
		/// <param name="xml">string workflow markup to deserialize</param>
		/// <param name="obj">Output DocumentsResponseDocument object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool Deserialize(string xml, out DocumentsResponseDocument obj, out System.Exception exception)
		{
			exception = null;
			obj = default(DocumentsResponseDocument);
			try
			{
				obj = Deserialize(xml);
				return true;
			}
			catch (System.Exception ex)
			{
				exception = ex;
				return false;
			}
		}

		public static bool Deserialize(string xml, out DocumentsResponseDocument obj)
		{
			System.Exception exception = null;
			return Deserialize(xml, out obj, out exception);
		}

		public static DocumentsResponseDocument Deserialize(string xml)
		{
			System.IO.StringReader stringReader = null;
			try
			{
				stringReader = new System.IO.StringReader(xml);
				return ((DocumentsResponseDocument)(Serializer.Deserialize(System.Xml.XmlReader.Create(stringReader))));
			}
			finally
			{
				if ((stringReader != null))
				{
					stringReader.Dispose();
				}
			}
		}

		/// <summary>
		/// Serializes current DocumentsResponseDocument object into file
		/// </summary>
		/// <param name="fileName">full path of outupt xml file</param>
		/// <param name="exception">output Exception value if failed</param>
		/// <returns>true if can serialize and save into file; otherwise, false</returns>
		public virtual bool SaveToFile(string fileName, out System.Exception exception)
		{
			exception = null;
			try
			{
				SaveToFile(fileName);
				return true;
			}
			catch (System.Exception e)
			{
				exception = e;
				return false;
			}
		}

		public virtual void SaveToFile(string fileName)
		{
			System.IO.StreamWriter streamWriter = null;
			try
			{
				string xmlString = Serialize();
				System.IO.FileInfo xmlFile = new System.IO.FileInfo(fileName);
				streamWriter = xmlFile.CreateText();
				streamWriter.WriteLine(xmlString);
				streamWriter.Close();
			}
			finally
			{
				if ((streamWriter != null))
				{
					streamWriter.Dispose();
				}
			}
		}

		/// <summary>
		/// Deserializes xml markup from file into an DocumentsResponseDocument object
		/// </summary>
		/// <param name="fileName">string xml file to load and deserialize</param>
		/// <param name="obj">Output DocumentsResponseDocument object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool LoadFromFile(string fileName, out DocumentsResponseDocument obj, out System.Exception exception)
		{
			exception = null;
			obj = default(DocumentsResponseDocument);
			try
			{
				obj = LoadFromFile(fileName);
				return true;
			}
			catch (System.Exception ex)
			{
				exception = ex;
				return false;
			}
		}

		public static bool LoadFromFile(string fileName, out DocumentsResponseDocument obj)
		{
			System.Exception exception = null;
			return LoadFromFile(fileName, out obj, out exception);
		}

		public static DocumentsResponseDocument LoadFromFile(string fileName)
		{
			System.IO.FileStream file = null;
			System.IO.StreamReader sr = null;
			try
			{
				file = new System.IO.FileStream(fileName, FileMode.Open, FileAccess.Read);
				sr = new System.IO.StreamReader(file);
				string xmlString = sr.ReadToEnd();
				sr.Close();
				file.Close();
				return Deserialize(xmlString);
			}
			finally
			{
				if ((file != null))
				{
					file.Dispose();
				}
				if ((sr != null))
				{
					sr.Dispose();
				}
			}
		}
		#endregion
	}

	[System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.7.2612.0")]
	[System.SerializableAttribute()]
	[System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "http://www.minprom.gov.ru/schemas/licensing/Documents/1.0.0")]
	public enum DocumentsResponseDocumentDirection
	{

		/// <remarks/>
		Импорт,

		/// <remarks/>
		Экспорт,
	}

	[System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.7.2612.0")]
	[System.SerializableAttribute()]
	[System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "http://www.minprom.gov.ru/schemas/licensing/Documents/1.0.0")]
	public enum DocumentsResponseDocumentConfirmationStatus
	{

		/// <remarks/>
		[System.Xml.Serialization.XmlEnumAttribute("1")]
		Item1,

		/// <remarks/>
		[System.Xml.Serialization.XmlEnumAttribute("2")]
		Item2,
	}

	[System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.7.2612.0")]
	[System.SerializableAttribute()]
	[System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "http://www.minprom.gov.ru/schemas/licensing/Documents/1.0.0")]
	public enum DocumentsResponseDocumentDocumentType
	{

		/// <remarks/>
		[System.Xml.Serialization.XmlEnumAttribute("1")]
		Item1,

		/// <remarks/>
		[System.Xml.Serialization.XmlEnumAttribute("2")]
		Item2,
	}
}
