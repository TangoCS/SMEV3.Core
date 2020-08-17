using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.Xml;
using System.Xml.Serialization;
using GostCryptography.Cryptography;
using GostCryptography.Pkcs;
using GostCryptography.Xml;
using GostCryptography.Xml.SMEV;
using SMEV3.Behavior;
using SMEV3.FluentCassandra;
using SMEV3.Smev3Service;

namespace SMEV3
{
	public class Smev3Client : ISMEV3Service
	{
		SMEVMessageExchangePortTypeClient smev;
		Smev3Behavior behavior => new Smev3Behavior();
		bool testmessage;

		public string Url { get { return smev.Endpoint.Address.Uri.AbsoluteUri; } }

        /// <summary>
        /// Задание параметров клиента для сервиса СМЭВ 3 без файла конфигурации
        /// </summary>
        /// <param name="address">Адрес сервиса</param>
        /// <param name="proxy">Адрес прокси сервера</param>
        /// <param name="testmessage">тестовое сообщение</param>
        public Smev3Client(string address, string proxy = null, bool testmessage = false)
		{
			this.testmessage = testmessage;

            var binding = new BasicHttpBinding(BasicHttpSecurityMode.None)
            {
                Name = "SMEV3MessageMtomBinding",
                TransferMode = TransferMode.Buffered,
                MessageEncoding = WSMessageEncoding.Mtom,
                OpenTimeout = new TimeSpan(0, 1, 0), //по умолчанию 1 мин.
                SendTimeout = new TimeSpan(0, 3, 0), //по умолчанию 1 мин.
                ReceiveTimeout = new TimeSpan(0, 3, 0), //по умолчанию 10 мин.
                CloseTimeout = new TimeSpan(0, 1, 0), //по умолчанию 1 мин.
                MaxBufferSize = 6 * 1024 * 1024 // по умолчанию 65536 байт
            };
            binding.MaxReceivedMessageSize = binding.MaxBufferSize; // по умолчанию 65536 байт
			binding.MaxBufferPoolSize = binding.MaxBufferSize * 8; // по умолчанию 524288 байт

            ClientCredentials credential = null;
            if (!string.IsNullOrWhiteSpace(proxy))
            {
                string username = null;
                string password = null;
                var proxys = proxy.Split('@');
                string urlproxy = proxys[0];
                if (proxys.Length == 2)
                {
                    var logins = proxys[1].Split(':');
                    username = logins[0];
                    if (logins.Length > 1) password = logins[1];
                }
                binding.UseDefaultWebProxy = false;
                binding.BypassProxyOnLocal = true;
                binding.ProxyAddress = new Uri(urlproxy);

                if (!string.IsNullOrWhiteSpace(username) && !string.IsNullOrWhiteSpace(password))
                {
                    binding.Security.Mode = BasicHttpSecurityMode.TransportCredentialOnly;
                    binding.Security.Transport.ProxyCredentialType = HttpProxyCredentialType.Basic;
                    credential = new ClientCredentials();
                    credential.UserName.UserName = username;
                    credential.UserName.Password = password;
                }
            }

			smev = new SMEVMessageExchangePortTypeClient(binding, new EndpointAddress(address));
            if (credential != null)
            {
                smev.Endpoint.Behaviors.Remove(typeof(ClientCredentials));
                smev.Endpoint.Behaviors.Add(credential);
            }
            smev.Endpoint.Behaviors.Add(behavior);
		}

		#region Методы отправителя

		public ISMEV3Result SendRequest<T>(T requestData, IDictionary<string, byte[]> attachments)
		{
			var result = new SMEV3Result { MessageId = GuidGenerator.GenerateTimeBasedGuid().ToString() };
			try
			{
				var senderRequestData = new SenderProvidedRequestData();
				senderRequestData.Id = "SIGNED_BY_CONSUMER";
				senderRequestData.MessageID = result.MessageId;
				senderRequestData.ReferenceMessageID = senderRequestData.MessageID;

				if (testmessage)
					senderRequestData.TestMessage = new Smev3Service.Void();

				senderRequestData.MessagePrimaryContent = SerializeDetails<T>(requestData);

                AttachmentContentType[] contentList = null;
				if (attachments != null && attachments.Count > 0)
				{
					// передача будет через MTOM
					if (attachments.Sum(o => o.Value.Length) < 5242880)
					{
						var attachementHeaders = new List<AttachmentHeaderType>();
						var attachementContents = new List<AttachmentContentType>();

						foreach (var attachment in attachments)
						{
							var attachementHeader = new AttachmentHeaderType
							{
								contentId = attachment.Key,
								MimeType = "application/octet-stream",
								SignaturePKCS7 = SignedPkcs7.ComputeSignature(attachment.Value)
							};
							var attachementContent = new AttachmentContentType
							{
								Id = attachment.Key,
								Content = attachment.Value
							};
							attachementHeaders.Add(attachementHeader);
							attachementContents.Add(attachementContent);
						}
						senderRequestData.AttachmentHeaderList = attachementHeaders.ToArray();
						contentList = attachementContents.ToArray();
					}
					else // Передача через FTP
					{
						var refAttachements = new List<RefAttachmentHeaderType>();
						foreach (var attachment in attachments)
						{
							var uuid = GuidGenerator.GenerateTimeBasedGuid().ToString();

							FtpUpLoad(uuid, attachment.Key, attachment.Value);

							var hash = SignedPkcs7.ComputeDigest(attachment.Value);

							var refAttachement = new RefAttachmentHeaderType
							{
								uuid = uuid,
								Hash = Convert.ToBase64String(hash),
								MimeType = "application/octet-stream",
								SignaturePKCS7 = SignedPkcs7.ComputeSignatureDigest(hash)
							};
							refAttachements.Add(refAttachement);
						}
						senderRequestData.RefAttachmentHeaderList = refAttachements.ToArray();
					}
				}

				var request = new SendRequest(senderRequestData, null, null);
				var smevSign = SerializeWithSign(request, "SIGNED_BY_CONSUMER");
				request.CallerInformationSystemSignature = smevSign;
				request.AttachmentContentList = contentList;

				var response = smev.SendRequest(request);
				result.SoapRequest = behavior.SoapRequest;
				result.SoapResponse = behavior.SoapResponse;
				if (!response.MessageMetadata.StatusSpecified)
				{
					result.Status = SMEV3ResultStatus.OK;
					return result;
				}

				var status = response.MessageMetadata.Status;
				if (status == InteractionStatusType.requestIsQueued ||
					status == InteractionStatusType.requestIsAcceptedBySmev ||
					status == InteractionStatusType.underProcessing)
				{
					result.Status = SMEV3ResultStatus.OK;
				}
				else
				{
					result.Status = SMEV3ResultStatus.Fail;
					result.ErrorText = "Статус сообщения, обработка которого не была предусмотрена";
				}
			}
			catch (FaultException e)
			{
				result.SoapRequest = behavior.SoapRequest;
				result.SoapResponse = behavior.SoapResponse;
				result.Status = SMEV3ResultStatus.Fail;
				result.ErrorText = e.Message;
			}
			catch (Exception e)
			{
				result.Status = SMEV3ResultStatus.Error;
                result.ErrorText = "";
                while (e != null)
                {
                    result.ErrorText += e.Message + "\n";
                    result.ErrorText += e.StackTrace + "\n\n";
                    e = e.InnerException;
                }
            }

            return result;
		}

        /// <summary>
        /// После получения ответа необходимо подтвердить получение методом Ack
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="namespaceuri"></param>
        /// <param name="rootname">Имя корневого элемента вида сведений, если null, берется имя класса</param>
        /// <returns></returns>
        public ISMEV3Response GetResponse()
        {
            var result = new SMEV3ResponseResult();

            try
            {
                var messageSelector = new MessageTypeSelector();
                messageSelector.Id = "SIGNED_BY_CALLER";
                messageSelector.Timestamp = DateTime.Now;

                //var type = typeof(T);
                //var root = type.GetCustomAttributes(typeof(XmlRootAttribute), false).Select(o => (XmlRootAttribute)o).First();
                //messageSelector.RootElementLocalName = string.IsNullOrWhiteSpace(root.ElementName) ? type.Name : root.ElementName;
                //messageSelector.NamespaceURI = root.Namespace;

                var request = new GetResponse(messageSelector, null);
                var smevSign = SerializeWithSign(request, "SIGNED_BY_CALLER");
                request.CallerInformationSystemSignature = smevSign;

                var response = smev.GetResponse(request);
                result.SoapRequest = behavior.SoapRequest;
                result.SoapResponse = behavior.SoapResponse;

                if (response.ResponseMessage == null)
                {
                    result.Status = SMEV3ResultStatus.QueueEmpty;
                    return result;
                }

                var status = response.ResponseMessage.Response.MessageMetadata.Status;
                if (status == InteractionStatusType.responseIsDelivered)
                {
                    result.Status = SMEV3ResultStatus.OK;
                    result.MessageId = response.ResponseMessage.Response.SenderProvidedResponseData.MessageID;
                    result.OriginalMessageId = response.ResponseMessage.Response.OriginalMessageId;
                    result.MessageType = (SMEV3MessageType)response.ResponseMessage.Response.MessageMetadata.MessageType;

                    if (response.ResponseMessage.Response.SenderProvidedResponseData.MessagePrimaryContent != null)
                    {
                        result.ResponseData = response.ResponseMessage.Response.SenderProvidedResponseData.MessagePrimaryContent;

                        if (response.ResponseMessage.AttachmentContentList != null || response.ResponseMessage.Response.FSAttachmentsList != null)
                        {
                            result.Attachments = new Dictionary<string, byte[]>();
                        }

                        // Получение через MTOM
                        if (response.ResponseMessage.Response.SenderProvidedResponseData.AttachmentHeaderList != null)
                        {    
                            foreach (var attachmentContent in response.ResponseMessage.AttachmentContentList)
                            {
                                var filename = attachmentContent.Id;
                                /*var header = response.ResponseMessage.Response.SenderProvidedResponseData.AttachmentHeaderList.FirstOrDefault(o => o.contentId == attachmentContent.Id);
								if (header != null)
								{
									var ext = header.MimeType;
									filename += ext;
								}*/
                                result.Attachments.Add(filename, attachmentContent.Content);
                            }
                        }
                        // Получение через FTP
                        else if (response.ResponseMessage.Response.SenderProvidedResponseData.RefAttachmentHeaderList != null)
                        {   
                            foreach (var info in response.ResponseMessage.Response.FSAttachmentsList)
                            {
                                var bytes = FtpDownLoad(info);
                                result.Attachments.Add(info.FileName, bytes);
                            }
                        }
                    }
                    else if (response.ResponseMessage.Response.SenderProvidedResponseData.AsyncProcessingStatus != null)
                    {
                        var asyncstatus = response.ResponseMessage.Response.SenderProvidedResponseData.AsyncProcessingStatus;
                        result.OriginalMessageId = asyncstatus.OriginalMessageId;
                        result.Status = SMEV3ResultStatus.Reject;

                        if (asyncstatus.StatusCategory == InteractionStatusType.underProcessing ||
                            asyncstatus.StatusCategory == InteractionStatusType.requestIsQueued ||
                            asyncstatus.StatusCategory == InteractionStatusType.requestIsAcceptedBySmev ||
                            asyncstatus.StatusCategory == InteractionStatusType.responseIsAcceptedBySmev)
                        {
                            result.Status = SMEV3ResultStatus.UnderProcessing;
                        }
                        else if (asyncstatus.StatusCategory == InteractionStatusType.cancelled ||
                                asyncstatus.StatusCategory == InteractionStatusType.requestIsRejectedBySmev ||
                                asyncstatus.StatusCategory == InteractionStatusType.doesNotExist)
                        {
                            result.Status = SMEV3ResultStatus.Reject;
                        }
                        result.ErrorText = asyncstatus.SmevFault == null ? asyncstatus.StatusDetails :
                                (asyncstatus.StatusDetails + "\n" + asyncstatus.SmevFault.Code + " " + asyncstatus.SmevFault.Description);
                    }
                    else if (response.ResponseMessage.Response.SenderProvidedResponseData.RequestRejected != null)
                    {
                        var requestrejecteds = response.ResponseMessage.Response.SenderProvidedResponseData.RequestRejected;
                        result.OriginalMessageId = response.ResponseMessage.Response.OriginalMessageId;
                        foreach (var requestrejected in requestrejecteds)
                        {
                            result.ErrorText += requestrejected.RejectionReasonCode.ToString() + " " + requestrejected.RejectionReasonDescription;
                        }
                        result.Status = SMEV3ResultStatus.Reject;
                    }
                    // ------------- Пока непонятно нужно ли это обрабатывать ---------------
                    else if (response.ResponseMessage.Response.SenderProvidedResponseData.RequestStatus != null)
                    {
                        var requeststatus = response.ResponseMessage.Response.SenderProvidedResponseData.RequestStatus;
                        result.ErrorText = requeststatus.StatusDescription;
                        result.Status = SMEV3ResultStatus.UnderProcessing;
                    }
                }
                else
                {
                    result.Status = SMEV3ResultStatus.Fail;
                    result.ErrorText = "Статус сообщения, обработка которого не была предусмотрена";
                }
            }
            catch (FaultException e)
            {
                result.SoapRequest = behavior.SoapRequest;
                result.SoapResponse = behavior.SoapResponse;
                result.Status = SMEV3ResultStatus.Fail;
                result.ErrorText = e.Message;
            }
            catch (Exception e)
            {
                result.Status = SMEV3ResultStatus.Error;
                result.ErrorText = e.Message;
                result.ErrorText += "\n" + e.StackTrace;
            }

            return result;
        }

        #endregion

        #region Методы получателя

        /// <summary>
        /// После получения запроса необходимо подтвердить получение методом Ack
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        public ISMEV3Request<T> GetRequest<T>()
        {
            var result = new SMEV3RequestResult<T>();

            try
            {
                var messageSelector = new MessageTypeSelector();
                messageSelector.Id = "SIGNED_BY_CALLER";
                messageSelector.Timestamp = DateTime.Now;

                var type = typeof(T);
                var root = type.GetCustomAttributes(typeof(XmlRootAttribute), false).Select(o => (XmlRootAttribute)o).First();

                messageSelector.RootElementLocalName = string.IsNullOrWhiteSpace(root.ElementName) ? type.Name : root.ElementName;
                messageSelector.NamespaceURI = root.Namespace;

                var request = new GetRequest(messageSelector, null);
                var smevSign = SerializeWithSign(request, "SIGNED_BY_CALLER");
                request.CallerInformationSystemSignature = smevSign;

                var response = smev.GetRequest(request);
                result.SoapRequest = behavior.SoapRequest;
                result.SoapResponse = behavior.SoapResponse;

                if (response.RequestMessage == null)
                {
                    result.Status = SMEV3ResultStatus.QueueEmpty;
                    return result;
                }

                if (response.RequestMessage.Request != null)
                {
                    var requestInfo = response.RequestMessage.Request;
                    result.MessageId = requestInfo.SenderProvidedRequestData.MessageID;
                    result.Timestamp = requestInfo.MessageMetadata.SendingTimestamp;
                    result.ReplyTo = requestInfo.ReplyTo;
                    result.SenderMnemonic = requestInfo.MessageMetadata.Sender.Mnemonic;
                    result.RequestData = DeserializeDetails<T>(requestInfo.SenderProvidedRequestData.MessagePrimaryContent);
                    result.Status = SMEV3ResultStatus.OK;

                    if (response.RequestMessage.AttachmentContentList != null || requestInfo.FSAttachmentsList != null)
                    {
                        result.Attachments = new Dictionary<string, byte[]>();
                    }

                    // Получение через MTOM
                    if (requestInfo.SenderProvidedRequestData.AttachmentHeaderList != null)
                    {
                        foreach (var attachmentContent in response.RequestMessage.AttachmentContentList)
                        {
                            result.Attachments.Add(attachmentContent.Id, attachmentContent.Content);
                        }
                    }
                    // Получение через FTP
                    else if (requestInfo.SenderProvidedRequestData.RefAttachmentHeaderList != null)
                    {
                        foreach (var info in requestInfo.FSAttachmentsList)
                        {
                            var bytes = FtpDownLoad(info);
                            result.Attachments.Add(info.FileName, bytes);
                        }
                    }
                }
                // Пока непонятно нужно ли это обрабатывать
                else if (response.RequestMessage.Cancel != null)
                {
                    var cancel = response.RequestMessage.Cancel;
                    result.MessageId = cancel.MessageID;
                    result.SenderMnemonic = cancel.MessageMetadata.Sender.Mnemonic;
                    result.Timestamp = cancel.MessageMetadata.SendingTimestamp;
                    result.Status = SMEV3ResultStatus.Reject;
                }
            }
            catch (FaultException e)
            {
                result.SoapRequest = behavior.SoapRequest;
                result.SoapResponse = behavior.SoapResponse;
                result.Status = SMEV3ResultStatus.Fail;
                result.ErrorText = e.Message;
            }
            catch (Exception e)
            {
                result.Status = SMEV3ResultStatus.Error;
                result.ErrorText = e.Message;
                result.ErrorText += "\n" + e.StackTrace;
            }

            return result;
        }

        public ISMEV3Request<XmlElement> GetRequest()
        {
            var result = new SMEV3RequestResult<XmlElement>();

            try
            {
                var messageSelector = new MessageTypeSelector();
                messageSelector.Id = "SIGNED_BY_CALLER";
                messageSelector.Timestamp = DateTime.Now;

                var request = new GetRequest(messageSelector, null);
                var smevSign = SerializeWithSign(request, "SIGNED_BY_CALLER");
                request.CallerInformationSystemSignature = smevSign;

                var response = smev.GetRequest(request);
                result.SoapRequest = behavior.SoapRequest;
                result.SoapResponse = behavior.SoapResponse;

                if (response.RequestMessage == null)
                {
                    result.Status = SMEV3ResultStatus.QueueEmpty;
                    return result;
                }

                if (response.RequestMessage.Request != null)
                {
                    var requestInfo = response.RequestMessage.Request;
                    result.MessageId = requestInfo.SenderProvidedRequestData.MessageID;
                    result.Timestamp = requestInfo.MessageMetadata.SendingTimestamp;
                    result.ReplyTo = requestInfo.ReplyTo;
                    result.SenderMnemonic = requestInfo.MessageMetadata.Sender.Mnemonic;
                    result.RequestData = requestInfo.SenderProvidedRequestData.MessagePrimaryContent;
                    result.Status = SMEV3ResultStatus.OK;

                    if (response.RequestMessage.AttachmentContentList != null || requestInfo.FSAttachmentsList != null)
                    {
                        result.Attachments = new Dictionary<string, byte[]>();
                    }

                    // Получение через MTOM
                    if (requestInfo.SenderProvidedRequestData.AttachmentHeaderList != null)
                    {
                        foreach (var attachmentContent in response.RequestMessage.AttachmentContentList)
                        {
                            result.Attachments.Add(attachmentContent.Id, attachmentContent.Content);
                        }
                    }
                    // Получение через FTP
                    else if (requestInfo.SenderProvidedRequestData.RefAttachmentHeaderList != null)
                    {
                        foreach (var info in requestInfo.FSAttachmentsList)
                        {
                            var bytes = FtpDownLoad(info);
                            result.Attachments.Add(info.FileName, bytes);
                        }
                    }
                }
                // Пока непонятно нужно ли это обрабатывать
                else if (response.RequestMessage.Cancel != null)
                {
                    var cancel = response.RequestMessage.Cancel;
                    result.MessageId = cancel.MessageID;
                    result.SenderMnemonic = cancel.MessageMetadata.Sender.Mnemonic;
                    result.Timestamp = cancel.MessageMetadata.SendingTimestamp;
                    result.Status = SMEV3ResultStatus.Reject;
                }
            }
            catch (FaultException e)
            {
                result.SoapRequest = behavior.SoapRequest;
                result.SoapResponse = behavior.SoapResponse;
                result.Status = SMEV3ResultStatus.Fail;
                result.ErrorText = e.Message;
            }
            catch (Exception e)
            {
                result.Status = SMEV3ResultStatus.Error;
                result.ErrorText = e.Message;
                result.ErrorText += "\n" + e.StackTrace;
            }

            return result;
        }

        /// <summary>
        ///  Отправить ответ
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="responseTo">Адрес доставки ответа, подставляется в /To, берется из запроса потребителя /ReplyTo</param>
        /// <param name="responseData"></param>
        /// <param name="attachments"></param>
        /// <returns></returns>
        public ISMEV3Result SendResponse<T>(string responseTo, T responseData, IDictionary<string, byte[]> attachments)
		{
			var result = new SMEV3Result { MessageId = GuidGenerator.GenerateTimeBasedGuid().ToString() };
			try
			{
				var senderResponseData = new SenderProvidedResponseData();
				senderResponseData.Id = "SIGNED_BY_PROVIDER";
				senderResponseData.MessageID = result.MessageId;
				senderResponseData.To = responseTo;

				senderResponseData.MessagePrimaryContent = SerializeDetails<T>(responseData);

				AttachmentContentType[] contentList = null;
				if (attachments != null && attachments.Count > 0)
				{
					// передача будет через MTOM
					if (attachments.Sum(o => o.Value.Length) < 5242880)
					{
						var attachementHeaders = new List<AttachmentHeaderType>();
						var attachementContents = new List<AttachmentContentType>();

						foreach (var attachment in attachments)
						{
							var attachementHeader = new AttachmentHeaderType
							{
								contentId = attachment.Key,
								MimeType = "application/octet-stream",
								SignaturePKCS7 = SignedPkcs7.ComputeSignature(attachment.Value)
							};
							var attachementContent = new AttachmentContentType
							{
								Id = attachment.Key,
								Content = attachment.Value
							};
							attachementHeaders.Add(attachementHeader);
							attachementContents.Add(attachementContent);
						}
						contentList = attachementContents.ToArray();
						senderResponseData.AttachmentHeaderList = attachementHeaders.ToArray();
                    }
					else // Передача через FTP
					{
						var refattachements = new List<RefAttachmentHeaderType>();
                        foreach (var attachment in attachments)
						{
							var uuid = GuidGenerator.GenerateTimeBasedGuid().ToString();

							FtpUpLoad(uuid, attachment.Key, attachment.Value);

							var hash = SignedPkcs7.ComputeDigest(attachment.Value);

							var refAttachement = new RefAttachmentHeaderType
							{
								uuid = uuid,
								Hash = Convert.ToBase64String(hash),
								MimeType = "application/octet-stream",
								SignaturePKCS7 = SignedPkcs7.ComputeSignatureDigest(hash)
							};
							refattachements.Add(refAttachement);
						}
						senderResponseData.RefAttachmentHeaderList = refattachements.ToArray();
                    }
				}

				var request = new SendResponse(senderResponseData, null, null);
				var smevSign = SerializeWithSign(request, "SIGNED_BY_PROVIDER");
				request.CallerInformationSystemSignature = smevSign;
				request.AttachmentContentList = contentList;

				var response = smev.SendResponse(request);
				result.SoapRequest = behavior.SoapRequest;
				result.SoapResponse = behavior.SoapResponse;
				result.Status = SMEV3ResultStatus.OK;
			}
			catch (FaultException e)
			{
				result.SoapRequest = behavior.SoapRequest;
				result.SoapResponse = behavior.SoapResponse;
				result.Status = SMEV3ResultStatus.Fail;
				result.ErrorText = e.Message;
			}
			catch (Exception e)
			{
				result.Status = SMEV3ResultStatus.Error;
				result.ErrorText = e.Message;
				result.ErrorText += "\n" + e.StackTrace;
			}

			return result;
		}

        public ISMEV3Result SendReject(string responseTo, RejectCode rejectCode, string rejectDescription)
        {
            var result = new SMEV3Result { MessageId = GuidGenerator.GenerateTimeBasedGuid().ToString() };
            try
            {
                var senderResponseData = new SenderProvidedResponseData();
                senderResponseData.Id = "SIGNED_BY_PROVIDER";
                senderResponseData.MessageID = result.MessageId;
                senderResponseData.To = responseTo;

                senderResponseData.RequestRejected = new SenderProvidedResponseDataRequestRejected[]
                {
                    new SenderProvidedResponseDataRequestRejected
                    {
                         RejectionReasonCode = rejectCode,
                         RejectionReasonDescription = rejectDescription
                    }
                };

                var request = new SendResponse(senderResponseData, null, null);
                var smevSign = SerializeWithSign(request, "SIGNED_BY_PROVIDER");
                request.CallerInformationSystemSignature = smevSign;

                var response = smev.SendResponse(request);
                result.SoapRequest = behavior.SoapRequest;
                result.SoapResponse = behavior.SoapResponse;
                result.Status = SMEV3ResultStatus.OK;
            }
            catch (FaultException e)
            {
                result.SoapRequest = behavior.SoapRequest;
                result.SoapResponse = behavior.SoapResponse;
                result.Status = SMEV3ResultStatus.Fail;
                result.ErrorText = e.Message;
            }
            catch (Exception e)
            {
                result.Status = SMEV3ResultStatus.Error;
                result.ErrorText = e.Message;
                result.ErrorText += "\n" + e.StackTrace;
            }

            return result;
        }
        #endregion

        public ISMEV3Result Ack(string messageId)
		{
			var result = new SMEV3Result { MessageId = messageId };
			try
			{
				var ackMessage = new AckTargetMessage();
				ackMessage.Id = "SIGNED_BY_CALLER";
				ackMessage.accepted = true;
				ackMessage.Value = messageId;

				var request = new Ack(ackMessage, null);
				var smevSign = SerializeWithSign(request, "SIGNED_BY_CALLER");
				request.CallerInformationSystemSignature = smevSign;

				var response = smev.Ack(request);
				result.SoapRequest = behavior.SoapRequest;
				result.SoapResponse = behavior.SoapResponse;
				result.Status = SMEV3ResultStatus.OK;
			}
			catch (FaultException e)
			{
				result.SoapRequest = behavior.SoapRequest;
				result.SoapResponse = behavior.SoapResponse;
				result.Status = SMEV3ResultStatus.Fail;
				result.ErrorText = e.Message;
			}
			catch (Exception e)
			{
				result.Status = SMEV3ResultStatus.Error;
				result.ErrorText = e.Message;
				result.ErrorText += "\n" + e.StackTrace;
			}

			return result;
		}

		public ISMEV3Response GetStatus()
		{
			var result = new SMEV3ResponseResult();
			try
			{
				var timestamp = new Timestamp();
				timestamp.Id = "SIGNED_BY_CONSUMER";
				timestamp.Value = DateTime.UtcNow.ToString("o");

				var request = new GetStatus(timestamp, null);
				var smevSign = SerializeWithSign(request, "SIGNED_BY_CONSUMER");
				request.CallerInformationSystemSignature = smevSign;

				var response = smev.GetStatus(request);
				result.SoapRequest = behavior.SoapRequest;
				result.SoapResponse = behavior.SoapResponse;

				if (response.SmevAsyncProcessingMessage == null)
				{
					result.Status = SMEV3ResultStatus.QueueEmpty;
					return result;
				}
				var asyncstatus = response.SmevAsyncProcessingMessage.AsyncProcessingStatusData.AsyncProcessingStatus;
				result.MessageId = response.SmevAsyncProcessingMessage.AsyncProcessingStatusData.Id;
				result.OriginalMessageId = asyncstatus.OriginalMessageId;
				result.MessageType = SMEV3MessageType.Response;
				result.Status = SMEV3ResultStatus.Reject;

				if (asyncstatus.StatusCategory == InteractionStatusType.underProcessing ||
					asyncstatus.StatusCategory == InteractionStatusType.requestIsQueued ||
					asyncstatus.StatusCategory == InteractionStatusType.requestIsAcceptedBySmev ||
					asyncstatus.StatusCategory == InteractionStatusType.responseIsAcceptedBySmev)
				{
					result.Status = SMEV3ResultStatus.UnderProcessing;
				}
				else if (asyncstatus.StatusCategory == InteractionStatusType.cancelled ||
						asyncstatus.StatusCategory == InteractionStatusType.requestIsRejectedBySmev ||
						asyncstatus.StatusCategory == InteractionStatusType.doesNotExist)
				{
					result.Status = SMEV3ResultStatus.Reject;
				}
				result.ErrorText = asyncstatus.SmevFault == null ? asyncstatus.StatusDetails :
						(asyncstatus.StatusDetails + "\n" + asyncstatus.SmevFault.Code + " " + asyncstatus.SmevFault.Description);
			}
			catch (FaultException e)
			{
				result.SoapRequest = behavior.SoapRequest;
				result.SoapResponse = behavior.SoapResponse;
				result.Status = SMEV3ResultStatus.Fail;
				result.ErrorText = e.Message;
			}
			catch (Exception e)
			{
				result.Status = SMEV3ResultStatus.Error;
				result.ErrorText = e.Message;
				result.ErrorText += "\n" + e.StackTrace;
			}

			return result;
		}

		public ISMEV3Queue GetIncomingQueueStatistics()
		{
			var result = new SMEV3Queue();
			try
			{
				var timestamp = new Timestamp();
				timestamp.Id = "SIGNED_BY_CONSUMER";
				timestamp.Value = DateTime.UtcNow.ToString("o");

				var request = new GetIncomingQueueStatistics(null, timestamp, null);
				var smevSign = SerializeWithSign(request, "SIGNED_BY_CONSUMER");
				request.CallerInformationSystemSignature = smevSign;

				var response = smev.GetIncomingQueueStatistics(request);

				if (response.QueueStatistics == null || response.QueueStatistics.Count() == 0)
				{
					result.Status = SMEV3ResultStatus.QueueEmpty;
					return result;
				}
				result.Status = SMEV3ResultStatus.OK;
				result.RequestNumber = response.QueueStatistics.Where(o => o.queueName == "queue://delivery.MNPT03._REQUEST_").Select(o => o.pendingMessageNumberSpecified ? o.pendingMessageNumber : 0).Sum();
				result.ResponseNumber = response.QueueStatistics.Where(o => o.queueName == "queue://delivery.MNPT03._RESPONSE_").Select(o => o.pendingMessageNumberSpecified ? o.pendingMessageNumber : 0).Sum();
				result.StatusNumber = response.QueueStatistics.Where(o => o.queueName == "queue://delivery.MNPT03._STATUS_").Select(o => o.pendingMessageNumberSpecified ? o.pendingMessageNumber : 0).Sum();
			}
			catch (FaultException e)
			{
				result.Status = SMEV3ResultStatus.Fail;
				result.ErrorText = e.Message;
			}
			catch (Exception e)
			{
				result.Status = SMEV3ResultStatus.Error;
				result.ErrorText = e.Message;
				result.ErrorText += "\n" + e.StackTrace;
			}

			return result;
		}

		private static XmlElement SerializeDetails<T>(T data)
		{
			MemoryStream stream = null;
			try
			{
				XmlSerializerNamespaces ns = new XmlSerializerNamespaces();
				ns.Add(string.Empty, string.Empty);
                var ca = typeof(T).GetCustomAttributes(typeof(XmlTypeAttribute), false);
                if (ca.Length == 1)
                    ns.Add("ns1", ((XmlTypeAttribute)ca[0]).Namespace);

                var xmlSettings = new XmlWriterSettings();
				xmlSettings.NamespaceHandling = NamespaceHandling.OmitDuplicates;
				xmlSettings.OmitXmlDeclaration = true;
				xmlSettings.CloseOutput = false;

				stream = new MemoryStream();
				using (var xmlWriter = XmlWriter.Create(stream, xmlSettings))
				{
					var serializer = new XmlSerializer(typeof(T));
					serializer.Serialize(xmlWriter, data, ns);
				}
				stream.Position = 0;
				var doc = new XmlDocument();
				doc.Load(stream);

				return doc.DocumentElement;
			}
			finally
			{
				if ((stream != null)) stream.Dispose();
			}
		}

		private static T DeserializeDetails<T>(XmlElement data)
		{
			StringReader reader = null;
			try
			{
				var xmlSettings = new XmlReaderSettings();
				xmlSettings.IgnoreWhitespace = true;
				xmlSettings.CloseInput = false;

				reader = new StringReader(data.OuterXml);
				var serializer = new XmlSerializer(typeof(T));

				return (T)serializer.Deserialize(XmlReader.Create(reader, xmlSettings));
			}
			finally
			{
				if ((reader != null)) reader.Dispose();
			}
		}

		/// <summary>
		/// Сериализует класс сообщения, подписывает и возвращает xml подписи
		/// </summary>
		/// <typeparam name="T"></typeparam>
		/// <param name="data">Класс сообщения для подписи</param>
		/// <param name="id">Идентификатор подписываемого элемента</param>
		/// <returns></returns>
		private static XmlElement SerializeWithSign<T>(T data, string id)
		{
			MemoryStream stream = null;
			try
			{
				XmlRootAttribute root = new XmlRootAttribute();
				root.ElementName = "Root";
				root.Namespace = "urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1";
				root.IsNullable = false;

				XmlSerializerNamespaces ns = new XmlSerializerNamespaces();
				ns.Add(string.Empty, string.Empty);

				var xmlSettings = new XmlWriterSettings();
				xmlSettings.NamespaceHandling = NamespaceHandling.OmitDuplicates;
				xmlSettings.OmitXmlDeclaration = true;
				xmlSettings.CloseOutput = false;

				stream = new MemoryStream();
				using (var writer = XmlWriter.Create(stream, xmlSettings))
				{
					var serializer = new XmlSerializer(typeof(T), root);
					serializer.Serialize(writer, data, ns);
				}
				stream.Position = 0;
				return Smev3Signed(stream, id);
			}
			finally
			{
				if ((stream != null)) stream.Dispose();
			}
		}

		private static XmlElement Smev3Signed(Stream message, string id)
		{
			var document = new XmlDocument();
			document.PreserveWhitespace = false;
			document.Load(message);

			var signedXml = new SmevSignedXml(document);
			using (var key = GostCryptoConfig.CreateGost3410AsymmetricAlgorithm())
			{
				var reference = new Reference();

				reference.Uri = "#" + id;
				reference.AddTransform(new XmlDsigExcC14NTransform());
				reference.AddTransform(new XmlDsigSmevTransform());

				signedXml.SigningKey = key;
				signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

                if (GostCryptoConfig.ProviderType == ProviderTypes.CryptoPro256)
                {
                    signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigGost3410_2012_256Url;
                    reference.DigestMethod = SignedXml.XmlDsigGost3411_2012_256Url;
                }
                else if (GostCryptoConfig.ProviderType == ProviderTypes.CryptoPro512)
                {
                    signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigGost3410_2012_512Url;
                    reference.DigestMethod = SignedXml.XmlDsigGost3411_2012_512Url;
                }
                else
                {
                    signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigGost3410UrlObsolete;
                    reference.DigestMethod = SignedXml.XmlDsigGost3411UrlObsolete;
                }

                signedXml.AddReference(reference);

				var keyInfo = new KeyInfo();
				keyInfo.AddClause(new KeyInfoX509Data(key.ContainerCertificate));
				signedXml.KeyInfo = keyInfo;
				signedXml.ComputeSignature("ds");
			}
			var smevSign = signedXml.GetXml("ds");

			return smevSign;
		}

		private static bool FtpUpLoad(string uuid, string filename, byte[] data)
		{
			using (var webClient = new WebClient())
			{
				webClient.BaseAddress = "";
				webClient.Credentials = new NetworkCredential("anonymous", "anonymous");
				webClient.UploadData("/" + uuid + "/" + filename, data);
			}
			return true;
		}

		private static byte[] FtpDownLoad(FSAuthInfo info)
		{
			//ftp://логин:пароль@ip-адрес:порт/UUID/имя_файла
			byte[] bytes = null;
			using (var webClient = new WebClient())
			{
				webClient.BaseAddress = "";
				webClient.Credentials = new NetworkCredential(info.UserName, info.Password);
				bytes = webClient.DownloadData(info.uuid + "/" + info.FileName);
			}
			return bytes;
		}
	}

	public class SMEV3Queue : ISMEV3Queue
	{
		public long ResponseNumber { get; set; }
		public long RequestNumber { get; set; }
		public long StatusNumber { get; set; }
		public SMEV3ResultStatus Status { get; set; }
		public string ErrorText { get; set; }
	}

	public class SMEV3Result : ISMEV3Result
	{
		public string SoapRequest { get; set; }
		public string SoapResponse { get; set; }
		public string MessageId { get; set; }
		public SMEV3ResultStatus Status { get; set; }
		public string ErrorText { get; set; }
	}

	public class SMEV3ResponseResult : SMEV3Result, ISMEV3Response
	{
		public string OriginalMessageId { get; set; }
		public XmlElement ResponseData { get; set; }
		public IDictionary<string, byte[]> Attachments { get; set; }
		public SMEV3MessageType MessageType { get; set; }
	}

	public class SMEV3RequestResult<T> : SMEV3Result, ISMEV3Request<T>
	{
		public T RequestData { get; set; }
		public IDictionary<string, byte[]> Attachments { get; set; }
		public string SenderMnemonic { get; set; }
		public string ReplyTo { get; set; }
		public DateTime Timestamp { get; set; }
	}
}
