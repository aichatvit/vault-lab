/** @file SymmAlgMode.h
 * @brief Идентификаторы поддерживаемых режимов симметричного шифрования.
 */

#pragma once

#include <cstdint>

/**
 * \brief Идентификаторы режимов симметричного шифрования.
 */
enum class SymmAlgMode : int32_t
{
	/**
	 * \brief Режим простой замены.
	 */
	ecb,
	/**
	 * \brief Режим простой замены с зацеплением.
	 */
	cbc,
	/**
	 * \brief Режим выработки имитовставки.
	 */
	OMAC,
	cfb,
};