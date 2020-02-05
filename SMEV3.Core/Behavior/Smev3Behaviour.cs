using System;
using System.IO;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;

namespace SMEV3.Behavior
{
	public class Smev3Behavior : IEndpointBehavior
	{
		Smev3MessageInspector messageInspector = new Smev3MessageInspector();

		public string SoapRequest { get { return messageInspector.SoapRequest; } }
		public string SoapResponse { get { return messageInspector.SoapResponse; } }

		#region IEndpointBehavior Members

		public void ApplyClientBehavior(ServiceEndpoint serviceEndpoint, ClientRuntime behavior)
		{
			behavior.MessageInspectors.Add(messageInspector);
		}

		public void ApplyDispatchBehavior(ServiceEndpoint serviceEndpoint, EndpointDispatcher endpointDispatcher) { }
		public void AddBindingParameters(ServiceEndpoint serviceEndpoint, BindingParameterCollection bindingParameters) { }
		public void Validate(ServiceEndpoint serviceEndpoint) { }

		#endregion
	}

	public class Smev3MessageInspector : IClientMessageInspector
	{
		public string SoapRequest { get; private set; }
		public string SoapResponse { get; private set; }

		#region IClientMessageInspector Members

		public void AfterReceiveReply(ref Message message, object state)
		{
			SoapResponse = message.ToString();
			//File.WriteAllText(string.Format("response_{0}.xml", DateTime.Now.ToString("dd-MM-yyyy HH_mm_ss_ffff")), SoapResponse);
		}

		public object BeforeSendRequest(ref Message message, IClientChannel channel)
		{
			message.Headers.Clear();
			SoapRequest = message.ToString();
			//File.WriteAllText(string.Format("request_{0}.xml", DateTime.Now.ToString("dd-MM-yyyy HH_mm_ss_ffff")), SoapRequest);
			return null;
		}

		#endregion
	}
}