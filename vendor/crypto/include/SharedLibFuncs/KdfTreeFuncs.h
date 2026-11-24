/** @file KdfTreeFuncs.h
 * \brief Функции вывода ключей алгоритмом KDF_TREE_GOSTR3411_256.
 *
 * KDF_TREE_GOSTR3411_256 - алгоритм вывода ключей без состояния
 * (Р 50.1.113, раздел 4.5) на базе HMAC_GOSTR3411_2012_256:
 * KDFTREE256(Kin, label, seed, R) = K(1) | K(2) | K(3) | ...
 * где K(i) = HMAC256(Kin, [i]_b | label | 0x00 | seed | [L]_b).
 *
 * Предоставлены два интерфейса:
 *  - одноразовый (KdfTree_deriveBytes, KdfTree_deriveBytesBySymKey): криптографический
 *    объект создается и уничтожается внутри вызова, внешний контекст не нужен.
 *  - контекстный (KdfTree_createInst, KdfTree_deriveBytesInst,
 *    KdfTree_deriveBytesBySymKeyInst, KdfTree_deleteInst): переиспользуемый контекст
 *    создается один раз; ключ/label/seed/r передаются при каждом выводе;
 *    контекст освобождается через KdfTree_deleteInst.
 * Внешний фиксированный параметр r (1, 2 или 4) - ширина счетчика в байтах.
 * Длина выводимого ключевого материала не обязана быть кратна 32,
 * последний блок HMAC обрезается.
 */
#pragma once

#include <cstdint>
#include "../Common/SharedLibFuncsAtr.h"
#include "KdfTreeData.h"

extern "C"
{
/**
 * \brief Заполняет параметры и ограничения KDF_TREE_GOSTR3411_256 для заданного r.
 * Функция без состояния.
 * \param algDef идентификатор алгоритма. См. KdfTreeAlgDef.h
 * \param r параметр r алгоритма. Допустимые значения: 1, 2, 4. См. KdfTreeAlgDef.h
 * \param data указатель на структуру, в которую будут помещены данные. См. KdfTreeData.h
 * \param error_out указатель на код ошибки. См. SharedErrors.
 * \return true при успехе, false при ошибке.
 */
EXPORT bool CDECL KdfTree_getData(int32_t algDef, int32_t r, KdfTreeData* data, int32_t* error_out);
/**
 * \brief Выводит ключевой материал алгоритмом KDF_TREE_GOSTR3411_256.
 * Функция одноразовая: криптографический объект создается и уничтожается внутри функции.
 * \param cryptoContext контекст криптографии (создается initCryptoBySeq).
 * \param algDef идентификатор алгоритма. См. KdfTreeAlgDef.h
 * \param r параметр r алгоритма. Допустимые значения: 1, 2, 4. См. KdfTreeAlgDef.h
 * \param key ключ диверсификации (K_in).
 * \param lenOfKey длина ключа в байтах. Допустимый диапазон: 32..64.
 * \param label метка контекста. Не может быть пустой.
 * \param lenOfLabel длина метки в байтах.
 * \param seed seed контекста. Не может быть пустым.
 * \param lenOfSeed длина seed в байтах.
 * \param buf буфер для хранения выводимого ключевого материала.
 * \param sizeOfBuf длина выводимого ключевого материала в байтах.
 * Должна быть больше 0 и не превышать ограничение для данного r (см. KdfTree_getData).
 * Значение не обязано быть кратно 32, последний блок обрезается.
 * \param error_out указатель на код ошибки. См. SharedErrors.
 * \return true при успехе, false при ошибке.
 */
EXPORT bool CDECL KdfTree_deriveBytes(void* cryptoContext, int32_t algDef, int32_t r,
	const void* key, uint32_t lenOfKey,
	const void* label, uint32_t lenOfLabel,
	const void* seed, uint32_t lenOfSeed,
	void* buf, uint32_t sizeOfBuf, int32_t* error_out);
/**
 * \brief Выводит ключевой материал алгоритмом KDF_TREE_GOSTR3411_256 по контексту симметричного ключа.
 * Ключ диверсификации (K_in) извлекается из переданного контекста симметричного ключа
 * (тот же ключ, что возвращает sym_getKey) и освобождается внутри этой функции.
 * Вызывающий сохраняет полное владение контекстом ключа (symKey) и должен освободить его
 * через sym_deleteInst, когда он больше не нужен.
 * Остальной контракт (r, label, seed, размер ключа 32..64, ограничения вывода, ошибки)
 * совпадает с KdfTree_deriveBytes.
 */
EXPORT bool CDECL KdfTree_deriveBytesBySymKey(void* cryptoContext, int32_t algDef, int32_t r,
	void* symKey,
	const void* label, uint32_t lenOfLabel,
	const void* seed, uint32_t lenOfSeed,
	void* buf, uint32_t sizeOfBuf, int32_t* error_out);
/**
 * \brief Создает переиспользуемый контекст KDF_TREE_GOSTR3411_256.
 * Контекст инициализируется один раз и может использоваться для повторных выводов
 * (KdfTree_deriveBytesInst / KdfTree_deriveBytesBySymKeyInst) с разным
 * ключом/label/seed/r при каждом вызове.
 * Контекст не является потокобезопасным: используйте его из одного потока или
 * защищайте мьютексом. Последний ключ диверсификации остается внутри контекста
 * (во внутреннем HMAC) до следующего вывода или KdfTree_deleteInst.
 * Контекст должен быть освобожден через KdfTree_deleteInst.
 * \param cryptoContext контекст криптографии (создается initCryptoBySeq).
 * \param algDef идентификатор алгоритма. См. KdfTreeAlgDef.h
 * \param error_out указатель на код ошибки. См. SharedErrors.
 * \return указатель на созданный контекст или nullptr при ошибке.
 */
EXPORT void* CDECL KdfTree_createInst(void* cryptoContext, int32_t algDef, int32_t* error_out);
/**
 * \brief Освобождает контекст KDF, созданный KdfTree_createInst.
 * \param cryptoContext контекст криптографии (создается initCryptoBySeq).
 * \param kdfInst указатель на контекст, созданный KdfTree_createInst.
 * \return true при успехе, false при ошибке.
 */
EXPORT bool CDECL KdfTree_deleteInst(void* cryptoContext, void* kdfInst);
/**
 * \brief Выводит ключевой материал алгоритмом KDF_TREE_GOSTR3411_256 через переиспользуемый контекст.
 * Контекст (kdfInst) создается KdfTree_createInst. Ключ, label, seed и r
 * передаются при каждом вызове, поэтому один контекст выводит ключи для разных параметров.
 * Остальной контракт (r, размер ключа 32..64, label/seed не пусты, ограничения вывода,
 * ошибки) совпадает с KdfTree_deriveBytes.
 * \param kdfInst контекст, созданный KdfTree_createInst.
 * \param r параметр r алгоритма. Допустимые значения: 1, 2, 4. См. KdfTreeAlgDef.h
 * \param key ключ диверсификации (K_in).
 * \param lenOfKey длина ключа в байтах. Допустимый диапазон: 32..64.
 * \param label метка контекста. Не может быть пустой.
 * \param lenOfLabel длина метки в байтах.
 * \param seed seed контекста. Не может быть пустым.
 * \param lenOfSeed длина seed в байтах.
 * \param buf буфер для хранения выводимого ключевого материала.
 * \param sizeOfBuf длина выводимого ключевого материала в байтах.
 * Должна быть больше 0 и не превышать ограничение для данного r (см. KdfTree_getData).
 * Значение не обязано быть кратно 32, последний блок обрезается.
 * \param error_out указатель на код ошибки. См. SharedErrors.
 * \return true при успехе, false при ошибке.
 */
EXPORT bool CDECL KdfTree_deriveBytesInst(void* kdfInst, int32_t r,
	const void* key, uint32_t lenOfKey,
	const void* label, uint32_t lenOfLabel,
	const void* seed, uint32_t lenOfSeed,
	void* buf, uint32_t sizeOfBuf, int32_t* error_out);
/**
 * \brief Выводит ключевой материал алгоритмом KDF_TREE_GOSTR3411_256 через переиспользуемый контекст
 * и контекст симметричного ключа.
 * Ключ диверсификации (K_in) извлекается из переданного контекста симметричного ключа
 * (тот же ключ, что возвращает sym_getKey) и освобождается внутри этой функции.
 * Контекст KDF (kdfInst) создается KdfTree_createInst.
 * Вызывающий сохраняет полное владение контекстом ключа (symKey) и должен освободить его
 * через sym_deleteInst, когда он больше не нужен.
 * Остальной контракт (r, label, seed, размер ключа 32..64, ограничения вывода, ошибки)
 * совпадает с KdfTree_deriveBytes.
 * \param kdfInst контекст, созданный KdfTree_createInst.
 * \param r параметр r алгоритма. Допустимые значения: 1, 2, 4. См. KdfTreeAlgDef.h
 * \param symKey контекст симметричного ключа. См. SymmetricFuncs.h
 * \param label метка контекста. Не может быть пустой.
 * \param lenOfLabel длина метки в байтах.
 * \param seed seed контекста. Не может быть пустым.
 * \param lenOfSeed длина seed в байтах.
 * \param buf буфер для хранения выводимого ключевого материала.
 * \param sizeOfBuf длина выводимого ключевого материала в байтах.
 * \param error_out указатель на код ошибки. См. SharedErrors.
 * \return true при успехе, false при ошибке.
 */
EXPORT bool CDECL KdfTree_deriveBytesBySymKeyInst(void* kdfInst, int32_t r,
	void* symKey,
	const void* label, uint32_t lenOfLabel,
	const void* seed, uint32_t lenOfSeed,
	void* buf, uint32_t sizeOfBuf, int32_t* error_out);
}
