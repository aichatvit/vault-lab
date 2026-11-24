/** @file SymmAlgDef.h
 * @brief Идентификаторы поддерживаемых алгоритмов симметричного шифрования.
 */

#pragma once

#include <cstdint>

/**
 * \brief Алгоритмы симметричного шифрования.
 */
enum class SymmAlgDef : int32_t
{
	/**
	 * \brief ГОСТ 34.12. Кузнечик.
	 */
	Gost_34_12,
};