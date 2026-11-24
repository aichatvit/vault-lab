/** @file SymmAlgData.h
 * @brief Структура содержащая обобщенные данные симметричного алгоритма.
 */

#pragma once

#include <cstdint>

/**
 * \brief Данные симметричного алгоритма. 
 */
struct SymmAlgData
{
	/**
	 * \brief Длина ключа в байтах.
	 */
	uint32_t keySize;
	/**
	 * \brief Длина блока в байтах.
	 */
	uint32_t blockSize;
	/**
	 * \brief Длина вектора инициализации в байтах. В зависимости от выбранного режима шифрования может равняться нулю.
	 */
	uint32_t ivSize;
};