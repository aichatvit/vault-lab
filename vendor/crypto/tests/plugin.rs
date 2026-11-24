//! Интеграционные тесты плагина. Запускаются явно с --ignored и ALDCRYPTO_LIBRARY.
mod support;

use crypto::*;
use support::{Context, hex};

#[test]
#[ignore = "requires a trusted native plugin via ALDCRYPTO_LIBRARY"]
fn context_lifecycle() {
    for _ in 0..8 {
        drop(Context::new());
    }
}

#[test]
#[ignore = "requires a trusted native plugin via ALDCRYPTO_LIBRARY"]
fn random_generation() {
    let ctx = Context::new();
    let p = &ctx.plugin;
    let mut error = 0;
    // БЕЗОПАСНОСТЬ: размеры буферов соответствуют объявленным; родитель дочернего контекста жив.
    unsafe {
        let ptr = p.createRandInstance(ctx.ptr, RandomAlgDef_GostP1323565_1006_2017, &mut error);
        let rand = ctx.child(ptr, *p.deleteRandInstance.as_ref().unwrap());
        assert_eq!(error, 0);
        let mut first = [0u8; 64];
        let mut second = [0u8; 64];
        assert!(p.genRandSeq(ctx.ptr, rand.ptr, first.as_mut_ptr().cast(), 64, &mut error));
        assert_eq!(error, 0);
        assert!(p.genRandSeq(
            ctx.ptr,
            rand.ptr,
            second.as_mut_ptr().cast(),
            64,
            &mut error
        ));
        assert_eq!(error, 0);
        assert_ne!(first, [0; 64]);
        assert_ne!(first, second); // Базовая проверка, а не статистическое испытание генератора.
    }
}

#[test]
#[ignore = "requires a trusted native plugin via ALDCRYPTO_LIBRARY"]
fn hash_streaming_matches_one_shot() {
    let ctx = Context::new();
    let p = &ctx.plugin;
    // БЕЗОПАСНОСТЬ: размеры буферов соответствуют алгоритмам; контексты освобождаются.
    unsafe {
        for (kind, length) in [(HashLen_hash_256_bit, 32), (HashLen_hash_512_bit, 64)] {
            let mut error = 0;
            let ptr = p.createHashInst(ctx.ptr, HashAlgDef_gost, kind, &mut error);
            let hash = ctx.child(ptr, *p.deleteHashInst.as_ref().unwrap());
            assert_eq!(error, 0);
            let mut input: Vec<u8> = (0..1025).map(|i| (i % 251) as u8).collect();
            let mut expected = vec![0u8; length];
            let mut actual = vec![0u8; length];
            assert!(p.compHash_port(
                ctx.ptr,
                HashAlgDef_gost,
                kind,
                input.as_mut_ptr().cast(),
                input.len() as u32,
                expected.as_mut_ptr().cast(),
                &mut error
            ));
            assert_eq!(error, 0);
            for chunk in input.chunks_mut(73) {
                assert!(p.updateHash(
                    hash.ptr,
                    chunk.as_mut_ptr().cast(),
                    chunk.len() as u32,
                    &mut error
                ));
                assert_eq!(error, 0);
            }
            assert!(p.finalResult(hash.ptr, actual.as_mut_ptr().cast(), &mut error));
            assert_eq!(error, 0);
            assert_eq!(actual, expected);
        }
    }
}

#[test]
#[ignore = "requires a trusted native plugin via ALDCRYPTO_LIBRARY"]
fn kuznyechik_known_vector_and_key_allocation() {
    // RFC 7801, разделы 5.4–5.6: https://www.rfc-editor.org/rfc/rfc7801.html
    let ctx = Context::new();
    let p = &ctx.plugin;
    let key = hex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
    let plaintext = hex("1122334455667700ffeeddccbbaa9988");
    let expected = hex("7f679d90bebc24305a468d42b9d4edcd");
    let mut error = 0;
    // БЕЗОПАСНОСТЬ: ECB получает полный блок 16 байт без IV; длина ключа — 32 байта.
    unsafe {
        let ptr =
            p.sym_createSymAlgInstance(ctx.ptr, SymmAlgDef_Gost_34_12, SymmAlgMode_ecb, &mut error);
        let sym = ctx.child(ptr, *p.sym_deleteInst.as_ref().unwrap());
        assert_eq!(error, 0);
        let mut data = SymmAlgData::default();
        assert!(p.sym_getData(sym.ptr, &mut data, &mut error));
        assert_eq!(error, 0);
        assert!(data.keySize >= key.len() as u32);
        assert_eq!((data.blockSize, data.ivSize), (16, 0));
        assert!(p.sym_setKey(sym.ptr, key.as_ptr(), 32, &mut error));
        assert_eq!(error, 0);
        let mut encrypted = [0u8; 16];
        let mut decrypted = [0u8; 16];
        assert!(p.sym_encrypt(
            sym.ptr,
            plaintext.as_ptr(),
            16,
            encrypted.as_mut_ptr(),
            16,
            std::ptr::null(),
            0,
            &mut error
        ));
        assert_eq!(error, 0);
        assert_eq!(encrypted.as_slice(), expected);
        assert!(p.sym_decrypt(
            sym.ptr,
            encrypted.as_ptr(),
            16,
            decrypted.as_mut_ptr(),
            16,
            std::ptr::null(),
            0,
            &mut error
        ));
        assert_eq!(error, 0);
        assert_eq!(decrypted.as_slice(), plaintext);
        let mut length = 0;
        let exported = p.sym_getKey(sym.ptr, &mut length, &mut error);
        assert!(!exported.is_null(), "sym_getKey: {error}");
        // Копируем в пределах возвращённого буфера, затем освобождаем его до проверок.
        let bytes = std::slice::from_raw_parts(exported.cast::<u8>(), length as usize).to_vec();
        assert!(p.destroyMemory(ctx.ptr, exported, length));
        assert_eq!(error, 0);
        assert_eq!(bytes, key);
    }
}

#[test]
#[ignore = "requires a trusted native plugin via ALDCRYPTO_LIBRARY"]
fn hmac_known_vector_and_streaming() {
    // RFC 7836, приложение B, примеры 1 и 2.
    let ctx = Context::new();
    let p = &ctx.plugin;
    unsafe {
        for (kind, expected) in [
            (
                HmacLen_Hmac_256_bit,
                "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9",
            ),
            (
                HmacLen_Hmac_512_bit,
                "a59bab22ecae19c65fbde6e5f4e9f5d8549d31f037f9df9b905500e171923a773d5f1530f2ed7e964cb2eedc29e9ad2f3afe93b2814f79f5000ffc0366c251e6",
            ),
        ] {
            let mut key: Vec<u8> = (0..32).collect();
            if kind == HmacLen_Hmac_512_bit {
                // Эта библиотека отклоняет 32-байтовый ключ HMAC-512 с ошибкой 3.
                // Дополнение нулями до 64-байтового блока хеша эквивалентно для HMAC.
                key.resize(64, 0);
            }
            let mut sizes = HmacData_KeySizes::default();
            let mut sizes_error = 0;
            assert!(p.Hmac_getData_KeySizes(
                HmacAlgDef_HMAC_GOSTR3411_2012,
                kind,
                &mut sizes,
                &mut sizes_error
            ));
            assert_eq!(sizes_error, 0);
            eprintln!(
                "HMAC kind={kind}: key sizes {}..{}",
                sizes.minKeySize, sizes.maxKeySize
            );
            let mut input = hex("0126bdb87800af214341456563780100");
            let expected = hex(expected);
            let mut output = vec![0u8; expected.len()];
            let mut error = 0;
            // БЕЗОПАСНОСТЬ: размеры ключа и буферов соответствуют выбранному HMAC.
            let ptr = p.createHmacInst_key(
                ctx.ptr,
                HmacAlgDef_HMAC_GOSTR3411_2012,
                kind,
                key.as_mut_ptr().cast(),
                key.len() as u32,
                &mut error,
            );
            assert!(!ptr.is_null(), "createHmacInst_key kind={kind}: {error}");
            let hmac = ctx.child(ptr, *p.deleteHmacInst.as_ref().unwrap());
            assert_eq!(error, 0);
            assert!(p.compHmac(
                hmac.ptr,
                input.as_mut_ptr().cast(),
                input.len() as u32,
                output.as_mut_ptr().cast(),
                &mut error
            ));
            assert_eq!(error, 0);
            assert_eq!(output, expected);
            let ptr = p.createHmacInst_key(
                ctx.ptr,
                HmacAlgDef_HMAC_GOSTR3411_2012,
                kind,
                key.as_mut_ptr().cast(),
                key.len() as u32,
                &mut error,
            );
            let streaming = ctx.child(ptr, *p.deleteHmacInst.as_ref().unwrap());
            assert_eq!(error, 0);
            for chunk in input.chunks_mut(5) {
                assert!(p.updateHmac(
                    streaming.ptr,
                    chunk.as_mut_ptr().cast(),
                    chunk.len() as u32,
                    &mut error
                ));
                assert_eq!(error, 0);
            }
            let mut streamed = vec![0; output.len()];
            assert!(p.finalHmac(streaming.ptr, streamed.as_mut_ptr().cast(), &mut error));
            assert_eq!(error, 0);
            assert_eq!(streamed, output);
        }
    }
}

#[test]
#[ignore = "requires a trusted native plugin via ALDCRYPTO_LIBRARY"]
fn kdf_tree_known_vector_and_invalid_parameter() {
    // RFC 7836, приложение B, пример 10; r=1, L=512 бит.
    let ctx = Context::new();
    let p = &ctx.plugin;
    let key: Vec<u8> = (0..32).collect();
    let label = hex("26bdb878");
    let seed = hex("af21434145656378");
    let expected = hex(
        "22b6837845c6bef65ea71672b265831086d3c76aebe6dae91cad51d83f79d16b074c9330599d7f8d712fca54392f4ddde93751206b3584c8f43f9e6dc51531f9",
    );
    let mut error = 0;
    // БЕЗОПАСНОСТЬ: длины и буферы корректны; API явно отклоняет недопустимый r.
    unsafe {
        let mut data = KdfTreeData::default();
        assert!(p.KdfTree_getData(
            KdfTreeAlgDef_KDF_TREE_GOSTR3411_256,
            1,
            &mut data,
            &mut error
        ));
        assert_eq!(error, 0);
        assert_eq!((data.r, data.maxSizeOfOutput), (1, 8160));
        let mut output = [0u8; 64];
        assert!(p.KdfTree_deriveBytes(
            ctx.ptr,
            KdfTreeAlgDef_KDF_TREE_GOSTR3411_256,
            1,
            key.as_ptr().cast(),
            32,
            label.as_ptr().cast(),
            4,
            seed.as_ptr().cast(),
            8,
            output.as_mut_ptr().cast(),
            64,
            &mut error
        ));
        assert_eq!(error, 0);
        assert_eq!(output.as_slice(), expected);
        let ptr = p.KdfTree_createInst(ctx.ptr, KdfTreeAlgDef_KDF_TREE_GOSTR3411_256, &mut error);
        let kdf = ctx.child(ptr, *p.KdfTree_deleteInst.as_ref().unwrap());
        assert_eq!(error, 0);
        output.fill(0);
        assert!(p.KdfTree_deriveBytesInst(
            kdf.ptr,
            1,
            key.as_ptr().cast(),
            32,
            label.as_ptr().cast(),
            4,
            seed.as_ptr().cast(),
            8,
            output.as_mut_ptr().cast(),
            64,
            &mut error
        ));
        assert_eq!(error, 0);
        assert_eq!(output.as_slice(), expected);
        assert!(!p.KdfTree_getData(
            KdfTreeAlgDef_KDF_TREE_GOSTR3411_256,
            3,
            &mut data,
            &mut error
        ));
        assert_ne!(error, 0);
    }
}

#[test]
#[ignore = "requires a trusted native plugin via ALDCRYPTO_LIBRARY"]
fn all_header_exports_are_available() {
    let p = support::load();
    let mut missing = Vec::new();
    if p.createAsymmetricContext.is_err() {
        missing.push("createAsymmetricContext");
    }
    if p.destroyAsymmetricContext.is_err() {
        missing.push("destroyAsymmetricContext");
    }
    if p.importPublicData.is_err() {
        missing.push("importPublicData");
    }
    if p.exportPublicData.is_err() {
        missing.push("exportPublicData");
    }
    if p.asymm_importKeyByPass.is_err() {
        missing.push("asymm_importKeyByPass");
    }
    if p.asymm_exportKeyByPass.is_err() {
        missing.push("asymm_exportKeyByPass");
    }
    if p.encrypt.is_err() {
        missing.push("encrypt");
    }
    if p.decrypt.is_err() {
        missing.push("decrypt");
    }
    if p.createSymKeyContainerOnKkp.is_err() {
        missing.push("createSymKeyContainerOnKkp");
    }
    if p.getSymKeyFromContainerOnKkp.is_err() {
        missing.push("getSymKeyFromContainerOnKkp");
    }
    if p.createCryptoContextBySignSeq.is_err() {
        missing.push("createCryptoContextBySignSeq");
    }
    if p.createCryptoContextByKkp.is_err() {
        missing.push("createCryptoContextByKkp");
    }
    if p.createCryptoContext.is_err() {
        missing.push("createCryptoContext");
    }
    if p.createCryptoContextByParams.is_err() {
        missing.push("createCryptoContextByParams");
    }
    if p.destroyCryptoContext.is_err() {
        missing.push("destroyCryptoContext");
    }
    if p.createKkp.is_err() {
        missing.push("createKkp");
    }
    if p.destroyMemory.is_err() {
        missing.push("destroyMemory");
    }
    if p.getErrorsCodes.is_err() {
        missing.push("getErrorsCodes");
    }
    if p.BRa_kb_createContext.is_err() {
        missing.push("BRa_kb_createContext");
    }
    if p.BRa_kb_genSymbol.is_err() {
        missing.push("BRa_kb_genSymbol");
    }
    if p.BRa_kb_addSymbolWithTimeCheck.is_err() {
        missing.push("BRa_kb_addSymbolWithTimeCheck");
    }
    if p.BRa_kb_genResult.is_err() {
        missing.push("BRa_kb_genResult");
    }
    if p.BRa_kb_destroyMemory.is_err() {
        missing.push("BRa_kb_destroyMemory");
    }
    if p.BRa_kb_destroyContext.is_err() {
        missing.push("BRa_kb_destroyContext");
    }
    if p.DiffieHellman_setAdditionalPrivateParams.is_err() {
        missing.push("DiffieHellman_setAdditionalPrivateParams");
    }
    if p.DiffieHellman_getAdditionalPrivateParams.is_err() {
        missing.push("DiffieHellman_getAdditionalPrivateParams");
    }
    if p.DiffieHellman_exportDerivedKeyMaterialByPass.is_err() {
        missing.push("DiffieHellman_exportDerivedKeyMaterialByPass");
    }
    if p.DiffieHellman_deriveKeyMaterial.is_err() {
        missing.push("DiffieHellman_deriveKeyMaterial");
    }
    if p.DiffieHellman_exportPublicData.is_err() {
        missing.push("DiffieHellman_exportPublicData");
    }
    if p.DiffieHellman_importPublicData.is_err() {
        missing.push("DiffieHellman_importPublicData");
    }
    if p.DiffieHellman_exportByPass.is_err() {
        missing.push("DiffieHellman_exportByPass");
    }
    if p.DiffieHellman_importByPass.is_err() {
        missing.push("DiffieHellman_importByPass");
    }
    if p.DiffieHellman_deleteDiffHellInst.is_err() {
        missing.push("DiffieHellman_deleteDiffHellInst");
    }
    if p.DiffieHellman_createDiffHellInst.is_err() {
        missing.push("DiffieHellman_createDiffHellInst");
    }
    if p.createHashInst.is_err() {
        missing.push("createHashInst");
    }
    if p.deleteHashInst.is_err() {
        missing.push("deleteHashInst");
    }
    if p.compHash.is_err() {
        missing.push("compHash");
    }
    if p.compHash_port.is_err() {
        missing.push("compHash_port");
    }
    if p.updateHash.is_err() {
        missing.push("updateHash");
    }
    if p.finalResult.is_err() {
        missing.push("finalResult");
    }
    if p.Hmac_getData_KeySizes.is_err() {
        missing.push("Hmac_getData_KeySizes");
    }
    if p.Hmac_getData.is_err() {
        missing.push("Hmac_getData");
    }
    if p.createHmacInst_key.is_err() {
        missing.push("createHmacInst_key");
    }
    if p.createHmacInst.is_err() {
        missing.push("createHmacInst");
    }
    if p.deleteHmacInst.is_err() {
        missing.push("deleteHmacInst");
    }
    if p.setKeyInst.is_err() {
        missing.push("setKeyInst");
    }
    if p.compHmac.is_err() {
        missing.push("compHmac");
    }
    if p.updateHmac.is_err() {
        missing.push("updateHmac");
    }
    if p.finalHmac.is_err() {
        missing.push("finalHmac");
    }
    if p.KdfTree_getData.is_err() {
        missing.push("KdfTree_getData");
    }
    if p.KdfTree_deriveBytes.is_err() {
        missing.push("KdfTree_deriveBytes");
    }
    if p.KdfTree_deriveBytesBySymKey.is_err() {
        missing.push("KdfTree_deriveBytesBySymKey");
    }
    if p.KdfTree_createInst.is_err() {
        missing.push("KdfTree_createInst");
    }
    if p.KdfTree_deleteInst.is_err() {
        missing.push("KdfTree_deleteInst");
    }
    if p.KdfTree_deriveBytesInst.is_err() {
        missing.push("KdfTree_deriveBytesInst");
    }
    if p.KdfTree_deriveBytesBySymKeyInst.is_err() {
        missing.push("KdfTree_deriveBytesBySymKeyInst");
    }
    if p.KcF_FromBytes.is_err() {
        missing.push("KcF_FromBytes");
    }
    if p.KcF_GetPublicParam.is_err() {
        missing.push("KcF_GetPublicParam");
    }
    if p.KcF_DeleteContainer.is_err() {
        missing.push("KcF_DeleteContainer");
    }
    if p.createRandInstance.is_err() {
        missing.push("createRandInstance");
    }
    if p.deleteRandInstance.is_err() {
        missing.push("deleteRandInstance");
    }
    if p.genRandSeq.is_err() {
        missing.push("genRandSeq");
    }
    if p.checkSequence_port.is_err() {
        missing.push("checkSequence_port");
    }
    if p.sign_exportPublicData.is_err() {
        missing.push("sign_exportPublicData");
    }
    if p.sign_importPublicData.is_err() {
        missing.push("sign_importPublicData");
    }
    if p.sign_verify.is_err() {
        missing.push("sign_verify");
    }
    if p.sign.is_err() {
        missing.push("sign");
    }
    if p.sign_exportByPass.is_err() {
        missing.push("sign_exportByPass");
    }
    if p.sign_importByPass.is_err() {
        missing.push("sign_importByPass");
    }
    if p.sign_createSignAlgInstanse.is_err() {
        missing.push("sign_createSignAlgInstanse");
    }
    if p.sign_deleteSignInst.is_err() {
        missing.push("sign_deleteSignInst");
    }
    if p.sym_getData.is_err() {
        missing.push("sym_getData");
    }
    if p.sym_importKeyBySymAlg.is_err() {
        missing.push("sym_importKeyBySymAlg");
    }
    if p.sym_exportKeyBySymAlg.is_err() {
        missing.push("sym_exportKeyBySymAlg");
    }
    if p.sym_importKeyByAssymetricEncrypter.is_err() {
        missing.push("sym_importKeyByAssymetricEncrypter");
    }
    if p.sym_exportKeyByAssymetricEncrypter.is_err() {
        missing.push("sym_exportKeyByAssymetricEncrypter");
    }
    if p.sym_importKeyByPass.is_err() {
        missing.push("sym_importKeyByPass");
    }
    if p.sym_exportKeyByPass.is_err() {
        missing.push("sym_exportKeyByPass");
    }
    if p.sym_decrypt.is_err() {
        missing.push("sym_decrypt");
    }
    if p.sym_encrypt.is_err() {
        missing.push("sym_encrypt");
    }
    if p.sym_setKey.is_err() {
        missing.push("sym_setKey");
    }
    if p.sym_getKey.is_err() {
        missing.push("sym_getKey");
    }
    if p.sym_deleteInst.is_err() {
        missing.push("sym_deleteInst");
    }
    if p.sym_createSymAlgInstance.is_err() {
        missing.push("sym_createSymAlgInstance");
    }
    if p.sym_createSymAlgInstance_pass.is_err() {
        missing.push("sym_createSymAlgInstance_pass");
    }
    if p.encSymKey.is_err() {
        missing.push("encSymKey");
    }
    if p.decSymKey.is_err() {
        missing.push("decSymKey");
    }
    if p.setRandomSeq.is_err() {
        missing.push("setRandomSeq");
    }
    if p.encBySymKey.is_err() {
        missing.push("encBySymKey");
    }
    if p.decBySymKey.is_err() {
        missing.push("decBySymKey");
    }
    if p.encBySymKey_co.is_err() {
        missing.push("encBySymKey_co");
    }
    if p.decBySymKey_co.is_err() {
        missing.push("decBySymKey_co");
    }
    assert!(missing.is_empty(), "Missing plugin exports: {missing:?}");
}
