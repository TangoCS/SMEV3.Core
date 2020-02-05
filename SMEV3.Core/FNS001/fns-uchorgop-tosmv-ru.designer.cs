// ------------------------------------------------------------------------------
//  <auto-generated>
//    Generated by Xsd2Code. Version 3.4.0.32989
//    <NameSpace>SMEV3.FNS001</NameSpace><Collection>List</Collection><codeType>CSharp</codeType><EnableDataBinding>False</EnableDataBinding><EnableLazyLoading>False</EnableLazyLoading><TrackingChangesEnable>False</TrackingChangesEnable><GenTrackingClasses>False</GenTrackingClasses><HidePrivateFieldInIDE>False</HidePrivateFieldInIDE><EnableSummaryComment>False</EnableSummaryComment><VirtualProp>False</VirtualProp><IncludeSerializeMethod>True</IncludeSerializeMethod><UseBaseClass>False</UseBaseClass><GenBaseClass>False</GenBaseClass><GenerateCloneMethod>False</GenerateCloneMethod><GenerateDataContracts>False</GenerateDataContracts><CodeBaseTag>Net40</CodeBaseTag><SerializeMethodName>Serialize</SerializeMethodName><DeserializeMethodName>Deserialize</DeserializeMethodName><SaveToFileMethodName>SaveToFile</SaveToFileMethodName><LoadFromFileMethodName>LoadFromFile</LoadFromFileMethodName><GenerateXMLAttributes>True</GenerateXMLAttributes><OrderXMLAttrib>False</OrderXMLAttrib><EnableEncoding>False</EnableEncoding><AutomaticProperties>False</AutomaticProperties><GenerateShouldSerialize>False</GenerateShouldSerialize><DisableDebug>True</DisableDebug><PropNameSpecified>Default</PropNameSpecified><Encoder>UTF8</Encoder><CustomUsings></CustomUsings><ExcludeIncludedTypes>False</ExcludeIncludedTypes><EnableInitializeFields>True</EnableInitializeFields>
//  </auto-generated>
// ------------------------------------------------------------------------------
namespace SMEV3.FNS001
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
	[System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn://x-artefacts-fns-uchorgop-tosmv-ru/370_68/4.0.1")]
	[System.Xml.Serialization.XmlRootAttribute(Namespace = "urn://x-artefacts-fns-uchorgop-tosmv-ru/370_68/4.0.1", IsNullable = false)]
	public partial class FNSUchOrgOPRequest
	{

		private FNSUchOrgOPRequestСвЮЛ свЮЛField;

		private FNSUchOrgOPRequestЗапросЮЛ запросЮЛField;

		private string идДокField;

		private FNSUchOrgOPRequestТипИнф типИнфField;

		private static System.Xml.Serialization.XmlSerializer serializer;

		public FNSUchOrgOPRequest()
		{
			this.запросЮЛField = new FNSUchOrgOPRequestЗапросЮЛ();
			this.свЮЛField = new FNSUchOrgOPRequestСвЮЛ();
		}

		public FNSUchOrgOPRequestСвЮЛ СвЮЛ
		{
			get
			{
				return this.свЮЛField;
			}
			set
			{
				this.свЮЛField = value;
			}
		}

		public FNSUchOrgOPRequestЗапросЮЛ ЗапросЮЛ
		{
			get
			{
				return this.запросЮЛField;
			}
			set
			{
				this.запросЮЛField = value;
			}
		}

		[System.Xml.Serialization.XmlAttributeAttribute()]
		public string ИдДок
		{
			get
			{
				return this.идДокField;
			}
			set
			{
				this.идДокField = value;
			}
		}

		[System.Xml.Serialization.XmlAttributeAttribute()]
		public FNSUchOrgOPRequestТипИнф ТипИнф
		{
			get
			{
				return this.типИнфField;
			}
			set
			{
				this.типИнфField = value;
			}
		}

		private static System.Xml.Serialization.XmlSerializer Serializer
		{
			get
			{
				if ((serializer == null))
				{
					serializer = new System.Xml.Serialization.XmlSerializer(typeof(FNSUchOrgOPRequest));
				}
				return serializer;
			}
		}

		#region Serialize/Deserialize
		/// <summary>
		/// Serializes current FNSUchOrgOPRequest object into an XML document
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
		/// Deserializes workflow markup into an FNSUchOrgOPRequest object
		/// </summary>
		/// <param name="xml">string workflow markup to deserialize</param>
		/// <param name="obj">Output FNSUchOrgOPRequest object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool Deserialize(string xml, out FNSUchOrgOPRequest obj, out System.Exception exception)
		{
			exception = null;
			obj = default(FNSUchOrgOPRequest);
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

		public static bool Deserialize(string xml, out FNSUchOrgOPRequest obj)
		{
			System.Exception exception = null;
			return Deserialize(xml, out obj, out exception);
		}

		public static FNSUchOrgOPRequest Deserialize(string xml)
		{
			System.IO.StringReader stringReader = null;
			try
			{
				stringReader = new System.IO.StringReader(xml);
				return ((FNSUchOrgOPRequest)(Serializer.Deserialize(System.Xml.XmlReader.Create(stringReader))));
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
		/// Serializes current FNSUchOrgOPRequest object into file
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
		/// Deserializes xml markup from file into an FNSUchOrgOPRequest object
		/// </summary>
		/// <param name="fileName">string xml file to load and deserialize</param>
		/// <param name="obj">Output FNSUchOrgOPRequest object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool LoadFromFile(string fileName, out FNSUchOrgOPRequest obj, out System.Exception exception)
		{
			exception = null;
			obj = default(FNSUchOrgOPRequest);
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

		public static bool LoadFromFile(string fileName, out FNSUchOrgOPRequest obj)
		{
			System.Exception exception = null;
			return LoadFromFile(fileName, out obj, out exception);
		}

		public static FNSUchOrgOPRequest LoadFromFile(string fileName)
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
	[System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn://x-artefacts-fns-uchorgop-tosmv-ru/370_68/4.0.1")]
	public partial class FNSUchOrgOPRequestСвЮЛ
	{

		private string наимЮЛField;

		private string иННЮЛField;

		private string оГРНField;

		private static System.Xml.Serialization.XmlSerializer serializer;

		[System.Xml.Serialization.XmlAttributeAttribute()]
		public string НаимЮЛ
		{
			get
			{
				return this.наимЮЛField;
			}
			set
			{
				this.наимЮЛField = value;
			}
		}

		[System.Xml.Serialization.XmlAttributeAttribute()]
		public string ИННЮЛ
		{
			get
			{
				return this.иННЮЛField;
			}
			set
			{
				this.иННЮЛField = value;
			}
		}

		[System.Xml.Serialization.XmlAttributeAttribute()]
		public string ОГРН
		{
			get
			{
				return this.оГРНField;
			}
			set
			{
				this.оГРНField = value;
			}
		}

		private static System.Xml.Serialization.XmlSerializer Serializer
		{
			get
			{
				if ((serializer == null))
				{
					serializer = new System.Xml.Serialization.XmlSerializer(typeof(FNSUchOrgOPRequestСвЮЛ));
				}
				return serializer;
			}
		}

		#region Serialize/Deserialize
		/// <summary>
		/// Serializes current FNSUchOrgOPRequestСвЮЛ object into an XML document
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
		/// Deserializes workflow markup into an FNSUchOrgOPRequestСвЮЛ object
		/// </summary>
		/// <param name="xml">string workflow markup to deserialize</param>
		/// <param name="obj">Output FNSUchOrgOPRequestСвЮЛ object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool Deserialize(string xml, out FNSUchOrgOPRequestСвЮЛ obj, out System.Exception exception)
		{
			exception = null;
			obj = default(FNSUchOrgOPRequestСвЮЛ);
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

		public static bool Deserialize(string xml, out FNSUchOrgOPRequestСвЮЛ obj)
		{
			System.Exception exception = null;
			return Deserialize(xml, out obj, out exception);
		}

		public static FNSUchOrgOPRequestСвЮЛ Deserialize(string xml)
		{
			System.IO.StringReader stringReader = null;
			try
			{
				stringReader = new System.IO.StringReader(xml);
				return ((FNSUchOrgOPRequestСвЮЛ)(Serializer.Deserialize(System.Xml.XmlReader.Create(stringReader))));
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
		/// Serializes current FNSUchOrgOPRequestСвЮЛ object into file
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
		/// Deserializes xml markup from file into an FNSUchOrgOPRequestСвЮЛ object
		/// </summary>
		/// <param name="fileName">string xml file to load and deserialize</param>
		/// <param name="obj">Output FNSUchOrgOPRequestСвЮЛ object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool LoadFromFile(string fileName, out FNSUchOrgOPRequestСвЮЛ obj, out System.Exception exception)
		{
			exception = null;
			obj = default(FNSUchOrgOPRequestСвЮЛ);
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

		public static bool LoadFromFile(string fileName, out FNSUchOrgOPRequestСвЮЛ obj)
		{
			System.Exception exception = null;
			return LoadFromFile(fileName, out obj, out exception);
		}

		public static FNSUchOrgOPRequestСвЮЛ LoadFromFile(string fileName)
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
	[System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn://x-artefacts-fns-uchorgop-tosmv-ru/370_68/4.0.1")]
	public partial class FNSUchOrgOPRequestЗапросЮЛ
	{

		private string оГРНField;

		private string иННЮЛField;

		private string кППОПField;

		private static System.Xml.Serialization.XmlSerializer serializer;

		[System.Xml.Serialization.XmlAttributeAttribute()]
		public string ОГРН
		{
			get
			{
				return this.оГРНField;
			}
			set
			{
				this.оГРНField = value;
			}
		}

		[System.Xml.Serialization.XmlAttributeAttribute()]
		public string ИННЮЛ
		{
			get
			{
				return this.иННЮЛField;
			}
			set
			{
				this.иННЮЛField = value;
			}
		}

		[System.Xml.Serialization.XmlAttributeAttribute()]
		public string КППОП
		{
			get
			{
				return this.кППОПField;
			}
			set
			{
				this.кППОПField = value;
			}
		}

		private static System.Xml.Serialization.XmlSerializer Serializer
		{
			get
			{
				if ((serializer == null))
				{
					serializer = new System.Xml.Serialization.XmlSerializer(typeof(FNSUchOrgOPRequestЗапросЮЛ));
				}
				return serializer;
			}
		}

		#region Serialize/Deserialize
		/// <summary>
		/// Serializes current FNSUchOrgOPRequestЗапросЮЛ object into an XML document
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
		/// Deserializes workflow markup into an FNSUchOrgOPRequestЗапросЮЛ object
		/// </summary>
		/// <param name="xml">string workflow markup to deserialize</param>
		/// <param name="obj">Output FNSUchOrgOPRequestЗапросЮЛ object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool Deserialize(string xml, out FNSUchOrgOPRequestЗапросЮЛ obj, out System.Exception exception)
		{
			exception = null;
			obj = default(FNSUchOrgOPRequestЗапросЮЛ);
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

		public static bool Deserialize(string xml, out FNSUchOrgOPRequestЗапросЮЛ obj)
		{
			System.Exception exception = null;
			return Deserialize(xml, out obj, out exception);
		}

		public static FNSUchOrgOPRequestЗапросЮЛ Deserialize(string xml)
		{
			System.IO.StringReader stringReader = null;
			try
			{
				stringReader = new System.IO.StringReader(xml);
				return ((FNSUchOrgOPRequestЗапросЮЛ)(Serializer.Deserialize(System.Xml.XmlReader.Create(stringReader))));
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
		/// Serializes current FNSUchOrgOPRequestЗапросЮЛ object into file
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
		/// Deserializes xml markup from file into an FNSUchOrgOPRequestЗапросЮЛ object
		/// </summary>
		/// <param name="fileName">string xml file to load and deserialize</param>
		/// <param name="obj">Output FNSUchOrgOPRequestЗапросЮЛ object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool LoadFromFile(string fileName, out FNSUchOrgOPRequestЗапросЮЛ obj, out System.Exception exception)
		{
			exception = null;
			obj = default(FNSUchOrgOPRequestЗапросЮЛ);
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

		public static bool LoadFromFile(string fileName, out FNSUchOrgOPRequestЗапросЮЛ obj)
		{
			System.Exception exception = null;
			return LoadFromFile(fileName, out obj, out exception);
		}

		public static FNSUchOrgOPRequestЗапросЮЛ LoadFromFile(string fileName)
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
	[System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn://x-artefacts-fns-uchorgop-tosmv-ru/370_68/4.0.1")]
	public enum FNSUchOrgOPRequestТипИнф
	{

		/// <remarks/>
		ЗапрПостУч,

		/// <remarks/>
		ЗапрСнУч,

		/// <remarks/>
		ЗапрРегИО,
	}

	[System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.7.2102.0")]
	[System.SerializableAttribute()]
	[System.Diagnostics.DebuggerStepThroughAttribute()]
	[System.ComponentModel.DesignerCategoryAttribute("code")]
	[System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn://x-artefacts-fns-uchorgop-tosmv-ru/370_68/4.0.1")]
	[System.Xml.Serialization.XmlRootAttribute(Namespace = "urn://x-artefacts-fns-uchorgop-tosmv-ru/370_68/4.0.1", IsNullable = false)]
	public partial class FNSUchOrgOPResponse
	{

		private object itemField;

		private string идДокField;

		private static System.Xml.Serialization.XmlSerializer serializer;

		[System.Xml.Serialization.XmlElementAttribute("СвОрг", typeof(FNSUchOrgOPResponseСвОрг))]
		[System.Xml.Serialization.XmlElementAttribute("СтОрг", typeof(string))]
		public object Item
		{
			get
			{
				return this.itemField;
			}
			set
			{
				this.itemField = value;
			}
		}

		[System.Xml.Serialization.XmlAttributeAttribute()]
		public string ИдДок
		{
			get
			{
				return this.идДокField;
			}
			set
			{
				this.идДокField = value;
			}
		}

		private static System.Xml.Serialization.XmlSerializer Serializer
		{
			get
			{
				if ((serializer == null))
				{
					serializer = new System.Xml.Serialization.XmlSerializer(typeof(FNSUchOrgOPResponse));
				}
				return serializer;
			}
		}

		#region Serialize/Deserialize
		/// <summary>
		/// Serializes current FNSUchOrgOPResponse object into an XML document
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
		/// Deserializes workflow markup into an FNSUchOrgOPResponse object
		/// </summary>
		/// <param name="xml">string workflow markup to deserialize</param>
		/// <param name="obj">Output FNSUchOrgOPResponse object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool Deserialize(string xml, out FNSUchOrgOPResponse obj, out System.Exception exception)
		{
			exception = null;
			obj = default(FNSUchOrgOPResponse);
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

		public static bool Deserialize(string xml, out FNSUchOrgOPResponse obj)
		{
			System.Exception exception = null;
			return Deserialize(xml, out obj, out exception);
		}

		public static FNSUchOrgOPResponse Deserialize(string xml)
		{
			System.IO.StringReader stringReader = null;
			try
			{
				stringReader = new System.IO.StringReader(xml);
				return ((FNSUchOrgOPResponse)(Serializer.Deserialize(System.Xml.XmlReader.Create(stringReader))));
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
		/// Serializes current FNSUchOrgOPResponse object into file
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
		/// Deserializes xml markup from file into an FNSUchOrgOPResponse object
		/// </summary>
		/// <param name="fileName">string xml file to load and deserialize</param>
		/// <param name="obj">Output FNSUchOrgOPResponse object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool LoadFromFile(string fileName, out FNSUchOrgOPResponse obj, out System.Exception exception)
		{
			exception = null;
			obj = default(FNSUchOrgOPResponse);
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

		public static bool LoadFromFile(string fileName, out FNSUchOrgOPResponse obj)
		{
			System.Exception exception = null;
			return LoadFromFile(fileName, out obj, out exception);
		}

		public static FNSUchOrgOPResponse LoadFromFile(string fileName)
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
	[System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn://x-artefacts-fns-uchorgop-tosmv-ru/370_68/4.0.1")]
	public partial class FNSUchOrgOPResponseСвОрг
	{

		private FNSUchOrgOPResponseСвОргСвРегИО свРегИОField;

		private string иННЮЛField;

		private string кППОПField;

		private string кодНООПField;

		private string адресНООПField;

		private string датаУчОПField;

		private string наимОПField;

		private string адресМНОПField;

		private string датаСнУчОПField;

		private static System.Xml.Serialization.XmlSerializer serializer;

		public FNSUchOrgOPResponseСвОрг()
		{
			this.свРегИОField = new FNSUchOrgOPResponseСвОргСвРегИО();
		}

		public FNSUchOrgOPResponseСвОргСвРегИО СвРегИО
		{
			get
			{
				return this.свРегИОField;
			}
			set
			{
				this.свРегИОField = value;
			}
		}

		[System.Xml.Serialization.XmlAttributeAttribute()]
		public string ИННЮЛ
		{
			get
			{
				return this.иННЮЛField;
			}
			set
			{
				this.иННЮЛField = value;
			}
		}

		[System.Xml.Serialization.XmlAttributeAttribute()]
		public string КППОП
		{
			get
			{
				return this.кППОПField;
			}
			set
			{
				this.кППОПField = value;
			}
		}

		[System.Xml.Serialization.XmlAttributeAttribute()]
		public string КодНООП
		{
			get
			{
				return this.кодНООПField;
			}
			set
			{
				this.кодНООПField = value;
			}
		}

		[System.Xml.Serialization.XmlAttributeAttribute()]
		public string АдресНООП
		{
			get
			{
				return this.адресНООПField;
			}
			set
			{
				this.адресНООПField = value;
			}
		}

		[System.Xml.Serialization.XmlAttributeAttribute()]
		public string ДатаУчОП
		{
			get
			{
				return this.датаУчОПField;
			}
			set
			{
				this.датаУчОПField = value;
			}
		}

		[System.Xml.Serialization.XmlAttributeAttribute()]
		public string НаимОП
		{
			get
			{
				return this.наимОПField;
			}
			set
			{
				this.наимОПField = value;
			}
		}

		[System.Xml.Serialization.XmlAttributeAttribute()]
		public string АдресМНОП
		{
			get
			{
				return this.адресМНОПField;
			}
			set
			{
				this.адресМНОПField = value;
			}
		}

		[System.Xml.Serialization.XmlAttributeAttribute()]
		public string ДатаСнУчОП
		{
			get
			{
				return this.датаСнУчОПField;
			}
			set
			{
				this.датаСнУчОПField = value;
			}
		}

		private static System.Xml.Serialization.XmlSerializer Serializer
		{
			get
			{
				if ((serializer == null))
				{
					serializer = new System.Xml.Serialization.XmlSerializer(typeof(FNSUchOrgOPResponseСвОрг));
				}
				return serializer;
			}
		}

		#region Serialize/Deserialize
		/// <summary>
		/// Serializes current FNSUchOrgOPResponseСвОрг object into an XML document
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
		/// Deserializes workflow markup into an FNSUchOrgOPResponseСвОрг object
		/// </summary>
		/// <param name="xml">string workflow markup to deserialize</param>
		/// <param name="obj">Output FNSUchOrgOPResponseСвОрг object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool Deserialize(string xml, out FNSUchOrgOPResponseСвОрг obj, out System.Exception exception)
		{
			exception = null;
			obj = default(FNSUchOrgOPResponseСвОрг);
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

		public static bool Deserialize(string xml, out FNSUchOrgOPResponseСвОрг obj)
		{
			System.Exception exception = null;
			return Deserialize(xml, out obj, out exception);
		}

		public static FNSUchOrgOPResponseСвОрг Deserialize(string xml)
		{
			System.IO.StringReader stringReader = null;
			try
			{
				stringReader = new System.IO.StringReader(xml);
				return ((FNSUchOrgOPResponseСвОрг)(Serializer.Deserialize(System.Xml.XmlReader.Create(stringReader))));
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
		/// Serializes current FNSUchOrgOPResponseСвОрг object into file
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
		/// Deserializes xml markup from file into an FNSUchOrgOPResponseСвОрг object
		/// </summary>
		/// <param name="fileName">string xml file to load and deserialize</param>
		/// <param name="obj">Output FNSUchOrgOPResponseСвОрг object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool LoadFromFile(string fileName, out FNSUchOrgOPResponseСвОрг obj, out System.Exception exception)
		{
			exception = null;
			obj = default(FNSUchOrgOPResponseСвОрг);
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

		public static bool LoadFromFile(string fileName, out FNSUchOrgOPResponseСвОрг obj)
		{
			System.Exception exception = null;
			return LoadFromFile(fileName, out obj, out exception);
		}

		public static FNSUchOrgOPResponseСвОрг LoadFromFile(string fileName)
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
	[System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn://x-artefacts-fns-uchorgop-tosmv-ru/370_68/4.0.1")]
	public partial class FNSUchOrgOPResponseСвОргСвРегИО
	{

		private string кодСтрИОField;

		private string наимРОИОField;

		private string регНомИОField;

		private static System.Xml.Serialization.XmlSerializer serializer;

		[System.Xml.Serialization.XmlAttributeAttribute()]
		public string КодСтрИО
		{
			get
			{
				return this.кодСтрИОField;
			}
			set
			{
				this.кодСтрИОField = value;
			}
		}

		[System.Xml.Serialization.XmlAttributeAttribute()]
		public string НаимРОИО
		{
			get
			{
				return this.наимРОИОField;
			}
			set
			{
				this.наимРОИОField = value;
			}
		}

		[System.Xml.Serialization.XmlAttributeAttribute()]
		public string РегНомИО
		{
			get
			{
				return this.регНомИОField;
			}
			set
			{
				this.регНомИОField = value;
			}
		}

		private static System.Xml.Serialization.XmlSerializer Serializer
		{
			get
			{
				if ((serializer == null))
				{
					serializer = new System.Xml.Serialization.XmlSerializer(typeof(FNSUchOrgOPResponseСвОргСвРегИО));
				}
				return serializer;
			}
		}

		#region Serialize/Deserialize
		/// <summary>
		/// Serializes current FNSUchOrgOPResponseСвОргСвРегИО object into an XML document
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
		/// Deserializes workflow markup into an FNSUchOrgOPResponseСвОргСвРегИО object
		/// </summary>
		/// <param name="xml">string workflow markup to deserialize</param>
		/// <param name="obj">Output FNSUchOrgOPResponseСвОргСвРегИО object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool Deserialize(string xml, out FNSUchOrgOPResponseСвОргСвРегИО obj, out System.Exception exception)
		{
			exception = null;
			obj = default(FNSUchOrgOPResponseСвОргСвРегИО);
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

		public static bool Deserialize(string xml, out FNSUchOrgOPResponseСвОргСвРегИО obj)
		{
			System.Exception exception = null;
			return Deserialize(xml, out obj, out exception);
		}

		public static FNSUchOrgOPResponseСвОргСвРегИО Deserialize(string xml)
		{
			System.IO.StringReader stringReader = null;
			try
			{
				stringReader = new System.IO.StringReader(xml);
				return ((FNSUchOrgOPResponseСвОргСвРегИО)(Serializer.Deserialize(System.Xml.XmlReader.Create(stringReader))));
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
		/// Serializes current FNSUchOrgOPResponseСвОргСвРегИО object into file
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
		/// Deserializes xml markup from file into an FNSUchOrgOPResponseСвОргСвРегИО object
		/// </summary>
		/// <param name="fileName">string xml file to load and deserialize</param>
		/// <param name="obj">Output FNSUchOrgOPResponseСвОргСвРегИО object</param>
		/// <param name="exception">output Exception value if deserialize failed</param>
		/// <returns>true if this XmlSerializer can deserialize the object; otherwise, false</returns>
		public static bool LoadFromFile(string fileName, out FNSUchOrgOPResponseСвОргСвРегИО obj, out System.Exception exception)
		{
			exception = null;
			obj = default(FNSUchOrgOPResponseСвОргСвРегИО);
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

		public static bool LoadFromFile(string fileName, out FNSUchOrgOPResponseСвОргСвРегИО obj)
		{
			System.Exception exception = null;
			return LoadFromFile(fileName, out obj, out exception);
		}

		public static FNSUchOrgOPResponseСвОргСвРегИО LoadFromFile(string fileName)
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