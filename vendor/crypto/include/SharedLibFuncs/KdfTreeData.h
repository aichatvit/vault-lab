#pragma once

#include <cstdint>

/**
 * \brief Параметры и ограничения алгоритма KDF_TREE_GOSTR3411_256.
 * Заполняется функцией KdfTree_getData. Все ограничения заданы в байтах.
 */
struct KdfTreeData
{
	/**
	 * \brief Идентификатор алгоритма. См. KdfTreeAlgDef.h
	 */
	uint16_t algId;
	/**
	 * \brief Параметр r (1, 2 или 4).
	 */
	uint32_t r;
	/**
	 * \brief Минимальный размер ключа диверсификации в байтах.
	 */
	uint16_t minKeySize;
	/**
	 * \brief Максимальный размер ключа диверсификации в байтах.
	 */
	uint16_t maxKeySize;
	/**
	 * \brief Максимальный размер выводимого ключевого материала в байтах для данного r.
	 * Равен 256 * (2^(8*r) - 1) бит по Р 50.1.113, раздел 4.5.
	 */
	uint64_t maxSizeOfOutput;
};
