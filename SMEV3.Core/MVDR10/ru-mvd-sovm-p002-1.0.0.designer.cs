// ------------------------------------------------------------------------------
//  <auto-generated>
//    Generated by Xsd2Code. Version 3.4.0.32989
//    <NameSpace>SMEV3.MVDR10</NameSpace><Collection>List</Collection><codeType>CSharp</codeType><EnableDataBinding>False</EnableDataBinding><EnableLazyLoading>False</EnableLazyLoading><TrackingChangesEnable>False</TrackingChangesEnable><GenTrackingClasses>False</GenTrackingClasses><HidePrivateFieldInIDE>False</HidePrivateFieldInIDE><EnableSummaryComment>False</EnableSummaryComment><VirtualProp>False</VirtualProp><IncludeSerializeMethod>True</IncludeSerializeMethod><UseBaseClass>False</UseBaseClass><GenBaseClass>False</GenBaseClass><GenerateCloneMethod>False</GenerateCloneMethod><GenerateDataContracts>False</GenerateDataContracts><CodeBaseTag>Net40</CodeBaseTag><SerializeMethodName>Serialize</SerializeMethodName><DeserializeMethodName>Deserialize</DeserializeMethodName><SaveToFileMethodName>SaveToFile</SaveToFileMethodName><LoadFromFileMethodName>LoadFromFile</LoadFromFileMethodName><GenerateXMLAttributes>True</GenerateXMLAttributes><OrderXMLAttrib>False</OrderXMLAttrib><EnableEncoding>False</EnableEncoding><AutomaticProperties>False</AutomaticProperties><GenerateShouldSerialize>False</GenerateShouldSerialize><DisableDebug>True</DisableDebug><PropNameSpecified>Default</PropNameSpecified><Encoder>UTF8</Encoder><CustomUsings></CustomUsings><ExcludeIncludedTypes>False</ExcludeIncludedTypes><EnableInitializeFields>True</EnableInitializeFields>
//  </auto-generated>
// ------------------------------------------------------------------------------
namespace SMEV3.MVDR10
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


	[System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.7.2102.0")]
	[System.SerializableAttribute()]
	[System.Diagnostics.DebuggerStepThroughAttribute()]
	[System.ComponentModel.DesignerCategoryAttribute("code")]
	[System.Xml.Serialization.XmlTypeAttribute(Namespace = "urn://ru/mvd/sovm/p002/1.0.0")]
	[System.Xml.Serialization.XmlRootAttribute("request", Namespace = "urn://ru/mvd/sovm/p002/1.0.0", IsNullable = false)]
	public partial class RequestType
	{

		private RequestInfoType requestInfoField;

		private static System.Xml.Serialization.XmlSerializer serializer;

		public RequestType()
		{
			this.requestInfoField = new RequestInfoType();
		}

		public RequestInfoType requestInfo
		{
			get
			{
				return this.requestInfoField;
			}
			set
			{
				this.requestInfoField = value;
			}
		}

		private static System.Xml.Serialization.XmlSerializer Serializer
		{
			get
			{
				if ((serializer == null))
				{
					serializer = new System.Xml.Serialization.XmlSerializer(typeof(RequestType));
				}
				return serializer;
			}
		}

		#region Serialize/Deserialize
		/// <summary>
		/// Serializes current RequestType object into an XML document
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
		/// Deserializes workflow markup into an RequestType object
		/// </summary>
		/// <param name="xml">string workflow markup to deserialize</param>
		/// <param name="obj">Output RequestType object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool Deserialize(string xml, out RequestType obj, out System.Exception exception)
		{
			exception = null;
			obj = default(RequestType);
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

		public static bool Deserialize(string xml, out RequestType obj)
		{
			System.Exception exception = null;
			return Deserialize(xml, out obj, out exception);
		}

		public static RequestType Deserialize(string xml)
		{
			System.IO.StringReader stringReader = null;
			try
			{
				stringReader = new System.IO.StringReader(xml);
				return ((RequestType)(Serializer.Deserialize(System.Xml.XmlReader.Create(stringReader))));
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
		/// Serializes current RequestType object into file
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
		/// Deserializes xml markup from file into an RequestType object
		/// </summary>
		/// <param name="fileName">string xml file to load and deserialize</param>
		/// <param name="obj">Output RequestType object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool LoadFromFile(string fileName, out RequestType obj, out System.Exception exception)
		{
			exception = null;
			obj = default(RequestType);
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

		public static bool LoadFromFile(string fileName, out RequestType obj)
		{
			System.Exception exception = null;
			return LoadFromFile(fileName, out obj, out exception);
		}

		public static RequestType LoadFromFile(string fileName)
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

	[System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.7.2102.0")]
	[System.SerializableAttribute()]
	[System.Diagnostics.DebuggerStepThroughAttribute()]
	[System.ComponentModel.DesignerCategoryAttribute("code")]
	[System.Xml.Serialization.XmlTypeAttribute(Namespace = "urn://ru/mvd/sovm/p002/1.0.0")]
	[System.Xml.Serialization.XmlRootAttribute(Namespace = "urn://ru/mvd/sovm/p002/1.0.0", IsNullable = true)]
	public partial class RequestInfoType
	{

		private PhysicalPersonQualifiedNameType physicalPersonQualifiedNameTypeField;

		private System.DateTime birthDateField;

		private PassportRFType passportRFField;

		private string regionCodeField;

		private static System.Xml.Serialization.XmlSerializer serializer;

		public RequestInfoType()
		{
			this.passportRFField = new PassportRFType();
			this.physicalPersonQualifiedNameTypeField = new PhysicalPersonQualifiedNameType();
		}

		public PhysicalPersonQualifiedNameType physicalPersonQualifiedNameType
		{
			get
			{
				return this.physicalPersonQualifiedNameTypeField;
			}
			set
			{
				this.physicalPersonQualifiedNameTypeField = value;
			}
		}

		[System.Xml.Serialization.XmlElementAttribute(DataType = "date")]
		public System.DateTime birthDate
		{
			get
			{
				return this.birthDateField;
			}
			set
			{
				this.birthDateField = value;
			}
		}

		public PassportRFType passportRF
		{
			get
			{
				return this.passportRFField;
			}
			set
			{
				this.passportRFField = value;
			}
		}

		public string regionCode
		{
			get
			{
				return this.regionCodeField;
			}
			set
			{
				this.regionCodeField = value;
			}
		}

		private static System.Xml.Serialization.XmlSerializer Serializer
		{
			get
			{
				if ((serializer == null))
				{
					serializer = new System.Xml.Serialization.XmlSerializer(typeof(RequestInfoType));
				}
				return serializer;
			}
		}

		#region Serialize/Deserialize
		/// <summary>
		/// Serializes current RequestInfoType object into an XML document
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
		/// Deserializes workflow markup into an RequestInfoType object
		/// </summary>
		/// <param name="xml">string workflow markup to deserialize</param>
		/// <param name="obj">Output RequestInfoType object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool Deserialize(string xml, out RequestInfoType obj, out System.Exception exception)
		{
			exception = null;
			obj = default(RequestInfoType);
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

		public static bool Deserialize(string xml, out RequestInfoType obj)
		{
			System.Exception exception = null;
			return Deserialize(xml, out obj, out exception);
		}

		public static RequestInfoType Deserialize(string xml)
		{
			System.IO.StringReader stringReader = null;
			try
			{
				stringReader = new System.IO.StringReader(xml);
				return ((RequestInfoType)(Serializer.Deserialize(System.Xml.XmlReader.Create(stringReader))));
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
		/// Serializes current RequestInfoType object into file
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
		/// Deserializes xml markup from file into an RequestInfoType object
		/// </summary>
		/// <param name="fileName">string xml file to load and deserialize</param>
		/// <param name="obj">Output RequestInfoType object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool LoadFromFile(string fileName, out RequestInfoType obj, out System.Exception exception)
		{
			exception = null;
			obj = default(RequestInfoType);
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

		public static bool LoadFromFile(string fileName, out RequestInfoType obj)
		{
			System.Exception exception = null;
			return LoadFromFile(fileName, out obj, out exception);
		}

		public static RequestInfoType LoadFromFile(string fileName)
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

	[System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.7.2102.0")]
	[System.SerializableAttribute()]
	[System.Diagnostics.DebuggerStepThroughAttribute()]
	[System.ComponentModel.DesignerCategoryAttribute("code")]
	[System.Xml.Serialization.XmlTypeAttribute(Namespace = "urn://ru/mvd/sovm/commons/1.0.0")]
	public partial class PhysicalPersonQualifiedNameType
	{

		private string familyNameField;

		private string firstNameField;

		private string patronymicField;

		private static System.Xml.Serialization.XmlSerializer serializer;

		public string familyName
		{
			get
			{
				return this.familyNameField;
			}
			set
			{
				this.familyNameField = value;
			}
		}

		public string firstName
		{
			get
			{
				return this.firstNameField;
			}
			set
			{
				this.firstNameField = value;
			}
		}

		public string patronymic
		{
			get
			{
				return this.patronymicField;
			}
			set
			{
				this.patronymicField = value;
			}
		}

		private static System.Xml.Serialization.XmlSerializer Serializer
		{
			get
			{
				if ((serializer == null))
				{
					serializer = new System.Xml.Serialization.XmlSerializer(typeof(PhysicalPersonQualifiedNameType));
				}
				return serializer;
			}
		}

		#region Serialize/Deserialize
		/// <summary>
		/// Serializes current PhysicalPersonQualifiedNameType object into an XML document
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
		/// Deserializes workflow markup into an PhysicalPersonQualifiedNameType object
		/// </summary>
		/// <param name="xml">string workflow markup to deserialize</param>
		/// <param name="obj">Output PhysicalPersonQualifiedNameType object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool Deserialize(string xml, out PhysicalPersonQualifiedNameType obj, out System.Exception exception)
		{
			exception = null;
			obj = default(PhysicalPersonQualifiedNameType);
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

		public static bool Deserialize(string xml, out PhysicalPersonQualifiedNameType obj)
		{
			System.Exception exception = null;
			return Deserialize(xml, out obj, out exception);
		}

		public static PhysicalPersonQualifiedNameType Deserialize(string xml)
		{
			System.IO.StringReader stringReader = null;
			try
			{
				stringReader = new System.IO.StringReader(xml);
				return ((PhysicalPersonQualifiedNameType)(Serializer.Deserialize(System.Xml.XmlReader.Create(stringReader))));
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
		/// Serializes current PhysicalPersonQualifiedNameType object into file
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
		/// Deserializes xml markup from file into an PhysicalPersonQualifiedNameType object
		/// </summary>
		/// <param name="fileName">string xml file to load and deserialize</param>
		/// <param name="obj">Output PhysicalPersonQualifiedNameType object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool LoadFromFile(string fileName, out PhysicalPersonQualifiedNameType obj, out System.Exception exception)
		{
			exception = null;
			obj = default(PhysicalPersonQualifiedNameType);
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

		public static bool LoadFromFile(string fileName, out PhysicalPersonQualifiedNameType obj)
		{
			System.Exception exception = null;
			return LoadFromFile(fileName, out obj, out exception);
		}

		public static PhysicalPersonQualifiedNameType LoadFromFile(string fileName)
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

	[System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.7.2102.0")]
	[System.SerializableAttribute()]
	[System.Diagnostics.DebuggerStepThroughAttribute()]
	[System.ComponentModel.DesignerCategoryAttribute("code")]
	[System.Xml.Serialization.XmlTypeAttribute(Namespace = "urn://ru/mvd/sovm/commons/1.0.0")]
	public partial class PassportRFType
	{

		private string seriesField;

		private string numberField;

		private System.DateTime issueDateField;

		private string issuerCodeField;

		private static System.Xml.Serialization.XmlSerializer serializer;

		public string series
		{
			get
			{
				return this.seriesField;
			}
			set
			{
				this.seriesField = value;
			}
		}

		public string number
		{
			get
			{
				return this.numberField;
			}
			set
			{
				this.numberField = value;
			}
		}

		[System.Xml.Serialization.XmlElementAttribute(DataType = "date")]
		public System.DateTime issueDate
		{
			get
			{
				return this.issueDateField;
			}
			set
			{
				this.issueDateField = value;
			}
		}

		public string issuerCode
		{
			get
			{
				return this.issuerCodeField;
			}
			set
			{
				this.issuerCodeField = value;
			}
		}

		private static System.Xml.Serialization.XmlSerializer Serializer
		{
			get
			{
				if ((serializer == null))
				{
					serializer = new System.Xml.Serialization.XmlSerializer(typeof(PassportRFType));
				}
				return serializer;
			}
		}

		#region Serialize/Deserialize
		/// <summary>
		/// Serializes current PassportRFType object into an XML document
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
		/// Deserializes workflow markup into an PassportRFType object
		/// </summary>
		/// <param name="xml">string workflow markup to deserialize</param>
		/// <param name="obj">Output PassportRFType object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool Deserialize(string xml, out PassportRFType obj, out System.Exception exception)
		{
			exception = null;
			obj = default(PassportRFType);
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

		public static bool Deserialize(string xml, out PassportRFType obj)
		{
			System.Exception exception = null;
			return Deserialize(xml, out obj, out exception);
		}

		public static PassportRFType Deserialize(string xml)
		{
			System.IO.StringReader stringReader = null;
			try
			{
				stringReader = new System.IO.StringReader(xml);
				return ((PassportRFType)(Serializer.Deserialize(System.Xml.XmlReader.Create(stringReader))));
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
		/// Serializes current PassportRFType object into file
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
		/// Deserializes xml markup from file into an PassportRFType object
		/// </summary>
		/// <param name="fileName">string xml file to load and deserialize</param>
		/// <param name="obj">Output PassportRFType object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool LoadFromFile(string fileName, out PassportRFType obj, out System.Exception exception)
		{
			exception = null;
			obj = default(PassportRFType);
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

		public static bool LoadFromFile(string fileName, out PassportRFType obj)
		{
			System.Exception exception = null;
			return LoadFromFile(fileName, out obj, out exception);
		}

		public static PassportRFType LoadFromFile(string fileName)
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

	[System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.7.2102.0")]
	[System.SerializableAttribute()]
	[System.Diagnostics.DebuggerStepThroughAttribute()]
	[System.ComponentModel.DesignerCategoryAttribute("code")]
	[System.Xml.Serialization.XmlTypeAttribute(Namespace = "urn://ru/mvd/sovm/p002/1.0.0")]
	[System.Xml.Serialization.XmlRootAttribute("response", Namespace = "urn://ru/mvd/sovm/p002/1.0.0", IsNullable = false)]
	public partial class ResponseType
	{

		private RequestInfoType requestInfoField;

		private ResponseInfoType responseInfoField;

		private static System.Xml.Serialization.XmlSerializer serializer;

		public ResponseType()
		{
			this.responseInfoField = new ResponseInfoType();
			this.requestInfoField = new RequestInfoType();
		}

		public RequestInfoType requestInfo
		{
			get
			{
				return this.requestInfoField;
			}
			set
			{
				this.requestInfoField = value;
			}
		}

		public ResponseInfoType responseInfo
		{
			get
			{
				return this.responseInfoField;
			}
			set
			{
				this.responseInfoField = value;
			}
		}

		private static System.Xml.Serialization.XmlSerializer Serializer
		{
			get
			{
				if ((serializer == null))
				{
					serializer = new System.Xml.Serialization.XmlSerializer(typeof(ResponseType));
				}
				return serializer;
			}
		}

		#region Serialize/Deserialize
		/// <summary>
		/// Serializes current ResponseType object into an XML document
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
		/// Deserializes workflow markup into an ResponseType object
		/// </summary>
		/// <param name="xml">string workflow markup to deserialize</param>
		/// <param name="obj">Output ResponseType object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool Deserialize(string xml, out ResponseType obj, out System.Exception exception)
		{
			exception = null;
			obj = default(ResponseType);
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

		public static bool Deserialize(string xml, out ResponseType obj)
		{
			System.Exception exception = null;
			return Deserialize(xml, out obj, out exception);
		}

		public static ResponseType Deserialize(string xml)
		{
			System.IO.StringReader stringReader = null;
			try
			{
				stringReader = new System.IO.StringReader(xml);
				return ((ResponseType)(Serializer.Deserialize(System.Xml.XmlReader.Create(stringReader))));
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
		/// Serializes current ResponseType object into file
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
		/// Deserializes xml markup from file into an ResponseType object
		/// </summary>
		/// <param name="fileName">string xml file to load and deserialize</param>
		/// <param name="obj">Output ResponseType object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool LoadFromFile(string fileName, out ResponseType obj, out System.Exception exception)
		{
			exception = null;
			obj = default(ResponseType);
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

		public static bool LoadFromFile(string fileName, out ResponseType obj)
		{
			System.Exception exception = null;
			return LoadFromFile(fileName, out obj, out exception);
		}

		public static ResponseType LoadFromFile(string fileName)
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

	[System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.7.2102.0")]
	[System.SerializableAttribute()]
	[System.Diagnostics.DebuggerStepThroughAttribute()]
	[System.ComponentModel.DesignerCategoryAttribute("code")]
	[System.Xml.Serialization.XmlTypeAttribute(Namespace = "urn://ru/mvd/sovm/p002/1.0.0")]
	[System.Xml.Serialization.XmlRootAttribute(Namespace = "urn://ru/mvd/sovm/p002/1.0.0", IsNullable = true)]
	public partial class ResponseInfoType
	{

		private string docStatusField;

		private string invalidityReasonField;

		private System.DateTime invaliditySinceField;

		private bool invaliditySinceFieldSpecified;

		private string commentField;

		private static System.Xml.Serialization.XmlSerializer serializer;

		public string docStatus
		{
			get
			{
				return this.docStatusField;
			}
			set
			{
				this.docStatusField = value;
			}
		}

		public string invalidityReason
		{
			get
			{
				return this.invalidityReasonField;
			}
			set
			{
				this.invalidityReasonField = value;
			}
		}

		[System.Xml.Serialization.XmlElementAttribute(DataType = "date")]
		public System.DateTime invaliditySince
		{
			get
			{
				return this.invaliditySinceField;
			}
			set
			{
				this.invaliditySinceField = value;
			}
		}

		[System.Xml.Serialization.XmlIgnoreAttribute()]
		public bool invaliditySinceSpecified
		{
			get
			{
				return this.invaliditySinceFieldSpecified;
			}
			set
			{
				this.invaliditySinceFieldSpecified = value;
			}
		}

		public string Comment
		{
			get
			{
				return this.commentField;
			}
			set
			{
				this.commentField = value;
			}
		}

		private static System.Xml.Serialization.XmlSerializer Serializer
		{
			get
			{
				if ((serializer == null))
				{
					serializer = new System.Xml.Serialization.XmlSerializer(typeof(ResponseInfoType));
				}
				return serializer;
			}
		}

		#region Serialize/Deserialize
		/// <summary>
		/// Serializes current ResponseInfoType object into an XML document
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
		/// Deserializes workflow markup into an ResponseInfoType object
		/// </summary>
		/// <param name="xml">string workflow markup to deserialize</param>
		/// <param name="obj">Output ResponseInfoType object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool Deserialize(string xml, out ResponseInfoType obj, out System.Exception exception)
		{
			exception = null;
			obj = default(ResponseInfoType);
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

		public static bool Deserialize(string xml, out ResponseInfoType obj)
		{
			System.Exception exception = null;
			return Deserialize(xml, out obj, out exception);
		}

		public static ResponseInfoType Deserialize(string xml)
		{
			System.IO.StringReader stringReader = null;
			try
			{
				stringReader = new System.IO.StringReader(xml);
				return ((ResponseInfoType)(Serializer.Deserialize(System.Xml.XmlReader.Create(stringReader))));
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
		/// Serializes current ResponseInfoType object into file
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
		/// Deserializes xml markup from file into an ResponseInfoType object
		/// </summary>
		/// <param name="fileName">string xml file to load and deserialize</param>
		/// <param name="obj">Output ResponseInfoType object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool LoadFromFile(string fileName, out ResponseInfoType obj, out System.Exception exception)
		{
			exception = null;
			obj = default(ResponseInfoType);
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

		public static bool LoadFromFile(string fileName, out ResponseInfoType obj)
		{
			System.Exception exception = null;
			return LoadFromFile(fileName, out obj, out exception);
		}

		public static ResponseInfoType LoadFromFile(string fileName)
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
}
