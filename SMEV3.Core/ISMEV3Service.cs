using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;

namespace SMEV3
{
	/// <summary>
	/// Интерфейс веб-сервиса СМЭВ 3
	/// </summary>
	public interface ISMEV3Service
	{
		#region Методы отправителя
		/// <summary>
		/// Отправить запрос
		/// </summary>
		/// <typeparam name="T">Тип запроса видов сведений</typeparam>
		/// <param name="requestData">Запрос вида сведений</param>
		/// <param name="attachments">Вложения</param>
		/// <returns></returns>
		ISMEV3Result SendRequest<T>(T requestData, IDictionary<string, byte[]> attachments);

		/// <summary>
		/// Получить ответ на запрос
		/// </summary>
		/// <typeparam name="T">Тип ответа видов сведений</typeparam>
		/// <returns></returns>
		ISMEV3Response GetResponse();
		#endregion

		#region Методы получателя
		/// <summary>
		/// Получить запрос
		/// </summary>
		/// <typeparam name="T">Тип запроса видов сведений</typeparam>
		/// <returns></returns>
		ISMEV3Request<T> GetRequest<T>();

		/// <summary>
		/// Отправить ответ
		/// </summary>
		/// <typeparam name="T">Тип ответа видов сведений</typeparam>
		/// <param name="responseTo">Кому отправляется ответ</param>
		/// <param name="responseData">Ответ вида сведений</param>
		/// <param name="attachments">Вложения</param>
		/// <returns></returns>
		ISMEV3Result SendResponse<T>(string responseTo, T responseData, IDictionary<string, byte[]> attachments);

        /// <summary>
        /// Отправить отказ
        /// </summary>
        /// <param name="responseTo">Кому отправляется ответ</param>
        /// <param name="rejectCode">Код отказа</param>
        /// <param name="rejectDescription">Описание</param>
        /// <returns></returns>
        ISMEV3Result SendReject(string responseTo, SMEV3.Smev3Service.RejectCode rejectCode, string rejectDescription);

        #endregion

        /// <summary>
        /// Подтвердить получение запроса или ответа
        /// </summary>
        /// <param name="messageId">Id СМЭВ-сообщения</param>
        ISMEV3Result Ack(string messageId);

		/// <summary>
		/// Запрос на получение ответа из очереди статусов
		/// </summary>
		/// <param name="datetime">Дата и время сообщения</param>
		ISMEV3Response GetStatus();

		/// <summary>
		/// Запрос на получение статистики входящих очередей
		/// </summary>
		/// <returns></returns>
		ISMEV3Queue GetIncomingQueueStatistics();
	}

	/// <summary>
	/// Статус результата взаимодействия со СМЭВ
	/// </summary>
	public enum SMEV3ResultStatus
	{
		OK, // Запрос отправлен или Ответ получен
		Fail, // Сбой (см. Текст ошибки)
		Error, // Ошибка, не связанная с процессом отправки/получения сообщения
		QueueEmpty, // Очередь запросов/ответов пуста
		UnderProcessing, // Запрос в обработке
		Reject // Запрос видов сведений отменен или отклонен
	}

	public enum SMEV3MessageType
	{
        Request,
        Broadcast,
        Response,
        Cancel
	}

	/// <summary>
	/// Результат взаимодействия со СМЭВ
	/// </summary>
	public interface ISMEV3Queue
	{
		/// <summary>
		/// Количество ответов в очереди
		/// </summary>
		long ResponseNumber { get; }
		/// <summary>
		/// Количество статусов в очереди
		/// </summary>
		long StatusNumber { get; }
		/// <summary>
		/// Количество запросов в очереди
		/// </summary>
		long RequestNumber { get; }
		/// <summary>
		/// Статус
		/// </summary>
		SMEV3ResultStatus Status { get; }
		/// <summary>
		/// Текст ошибки
		/// </summary>
		string ErrorText { get; }
	}
	/// <summary>
	/// Результат взаимодействия со СМЭВ
	/// </summary>
	public interface ISMEV3Result
	{
		/// <summary>
		/// Текст SOAP-запроса, который был отправлен в СМЭВ
		/// </summary>
		string SoapRequest { get; }
		/// <summary>
		/// Текст SOAP-ответа, который вернул СМЭВ в ответ на запрос
		/// </summary>
		string SoapResponse { get; }
		/// <summary>
		/// Id СМЭВ-сообщения
		/// </summary>
		string MessageId { get; }
		/// <summary>
		/// Статус
		/// </summary>
		SMEV3ResultStatus Status { get; }
		/// <summary>
		/// Текст ошибки
		/// </summary>
		string ErrorText { get; }
	}

	/// <summary>
	/// Запрос к поставщику видов сведений
	/// </summary>
	/// <typeparam name="T">Тип запроса видов сведений</typeparam>
	public interface ISMEV3Request<T> : ISMEV3Result
	{
		/// <summary>
		/// Данные запроса
		/// </summary>
		T RequestData { get; }
		/// <summary>
		/// Вложения
		/// </summary>
		IDictionary<string, byte[]> Attachments { get; }
		/// <summary>
		/// Мнемоника отправителя
		/// </summary>
		string SenderMnemonic { get; }
		/// <summary>
		/// Обратный адрес для копирования в //SenderProvidedResponseData/To при ответе
		/// </summary>
		string ReplyTo { get; }
		/// <summary>
		/// Метка времени получения в СМЭВ сообщения от ИС отправителя, начиная с которого отсчитывается срок исполнения запроса
		/// </summary>
		DateTime Timestamp { get; }
	}

	/// <summary>
	/// Ответ поставщика видов сведений
	/// </summary>
	/// <typeparam name="T">Тип ответа вида сведений</typeparam>
	public interface ISMEV3Response : ISMEV3Result
	{
		/// <summary>
		/// Id СМЭВ-сообщения отправленного для запроса
		/// </summary>
		string OriginalMessageId { get; }
		/// <summary>
		/// Данные ответа
		/// </summary>
		XmlElement ResponseData { get; }
		/// <summary>
		/// Вложения
		/// </summary>
		IDictionary<string, byte[]> Attachments { get; }
		
		SMEV3MessageType MessageType { get; }
	}

}
