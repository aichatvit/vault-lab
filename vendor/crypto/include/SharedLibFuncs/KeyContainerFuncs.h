/** @file HmacFuncs.h
 * \brief Функции для работы с крипто контейнерами, например ККП.
 *
 * Для использования функций необходимо создать крипто контекст. Для получения информации о параметрах контейнера,
 * должны использоваться идентификаторы из KeyContainerData.h.
 *
 */
#pragma once

#include <cstdint>
#include "../Common/SharedLibFuncsAtr.h"
#include "KeyContainerData.h"

extern "C" {
	/**
	 * \brief Создает контекст крипто контейнера, используя входную последовательность байт. Функция потокобезопасна.
	 * \param cryptoContext Главный криптоконтекст.
	 * \param containerType Тип контейнера.
	 * \param container Входная последовательность байт, представляющая контейнер KKP.
	 * \param lenOfContainer Длина входного конейтера - container, в байтах.
	 * \param conInstance_out Указатель на созданный контейкст ккп.
	 * \return Возвращаемый код ошибки.
	 */
	EXPORT int32_t CDECL KcF_FromBytes(void* cryptoContext, const std::uint32_t containerType, const void* container, 
		const std::uint32_t lenOfContainer, void** conInstance_out);
	/**
	 * \brief Создает контекст крипто контейнера, используя входную последовательность байт. Функция потокобезопасна.
	 * \param conInstance Указатель на контейкст ккп.
	 * \param containerType Тип контейнера.
	 * \param dataType Идентификатор открытых данных запрашиваемых из контейнера.
	 * \param data_out Указатель на выходную последовательность данных.
	 * \param len_out Указатель на выходную длину последовательность данных - data_out.
	 * \return Возвращаемый код ошибки.
	 */
	EXPORT int32_t CDECL KcF_GetPublicParam(const void* conInstance, const std::uint32_t containerType, 
		const std::uint32_t dataType, void** data_out, std::uint32_t* len_out);
	/**
	 * \brief Удаляет контейнер, созданный с помощью функции KcF_FromBytes.
	 * \param conInstance Указатель на контейкст ккп.
	 * \param containerType Тип контейнера.
	 * \param lenOfContainer Длина входного конейтера - container, в байтах.
	 * \return Возвращаемый код ошибки.
	 */
	EXPORT int32_t CDECL KcF_DeleteContainer(void* conInstance, const std::uint32_t containerType);
}