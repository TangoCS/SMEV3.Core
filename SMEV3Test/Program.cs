using System;
using GostCryptography.Cryptography;
using SMEV3;

namespace SMEV3Test
{
	public class Program
    {
        public static void Main(string[] args)
        {
			GostCryptoConfig.ProviderType = ProviderTypes.CryptoPro;
			var keyContainer = new System.Security.Cryptography.CspParameters();
			keyContainer.ProviderType = GostCryptoConfig.ProviderType;
			keyContainer.KeyNumber = 1;
			keyContainer.KeyContainerName = "REGISTRY\\\\CONTAINER_NAME";
			var ss = new System.Security.SecureString();
			foreach (char c in "12345678".ToCharArray())
				ss.AppendChar(c);
			keyContainer.KeyPassword = ss;
			GostCryptoConfig.KeyContainerParameters = keyContainer;

			RunWCFSmev3();
			Console.ReadKey();
		}

		static void RunWCFSmev3()
		{
            //http://smev3-d.test.gosuslugi.ru:7500/ws разработка
            //http://smev3-d.test.gosuslugi.ru:7500/smev/v1.1/ws разработка
            //http://smev3-d.test.gosuslugi.ru:7500/smev/v1.2/ws разработка
            //http://smev3-n0.test.gosuslugi.ru:7500/ws?wsdl тест
            //http://smev3-n0.test.gosuslugi.ru:7500/smev/v1.1/ws тест
            //http://smev3-n0.test.gosuslugi.ru:7500/smev/v1.2/ws тест

            var smev = new Smev3Client("http://smev3-n0.test.gosuslugi.ru:7500/smev/v1.1/ws");

			/*var vlsio = new SMEV3.RZDN01.lsio.RequestType();
			vlsio.Number = "RU/2016/11-00/16";
			vlsio.Date = DateTime.Parse("2016-01-01");

			var vnspp = new SMEV3.RZDN01.nspp.RequestType();
			vnspp.Number = "11-000000/16-1";
			vnspp.Date = DateTime.Parse("2016-01-01");

			var vot = new SMEV3.RZDN01.ot.RequestType();
			vot.Number = "RU/2016-01-0000/16";
			vot.Date = DateTime.Parse("2016-01-01");*/

			var st = smev.GetStatus();
			var qs = smev.GetIncomingQueueStatistics();
			if (qs.Status == SMEV3ResultStatus.Error || qs.Status == SMEV3ResultStatus.Fail)
			{
				Console.WriteLine(qs.ErrorText);
				return;
			}
			if (qs.Status == SMEV3ResultStatus.QueueEmpty)
			{
				Console.WriteLine("Очередь отсутствует.");
				return;
			}
			if (qs.ResponseNumber == 0)
			{
				Console.WriteLine("Очередь ответов пуста.");
				return;
			}
			else
			{
				Console.WriteLine(string.Format("В очереди ответов - {0}", qs.ResponseNumber));
				return;
			}

			/*var sr = smev.SendRequest(vlsio, null);
			if (sr.Status == SMEV3ResultStatus.OK)
			{
				Console.WriteLine("Запрос отправлен успешно.");
				Console.ReadKey();

				var gr = smev.GetResponse();
				if (gr.Status == SMEV3ResultStatus.OK || gr.Status == SMEV3ResultStatus.Reject)
				{
					Console.WriteLine("Ответ успешно получен.");
					Console.ReadKey();
					if (gr.MessageType == SMEV3MessageType.Response)
					{
						var a = smev.Ack(gr.MessageId);
						if (a.Status == SMEV3ResultStatus.OK)
						{
							Console.WriteLine("Подтвержение получения ответа отправлено.");
						}
					}
				}
			}*/
		}
	}
}
