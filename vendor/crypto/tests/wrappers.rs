use crypto::wrappers::{
    asymmetric::Asymmetric, base_crypt::BaseCrypt, bio_rand_kb::BioRandFlags,
    bio_rand_kb::BioRandKb, crypto_init_by_cont::CryptoInitByCont,
    crypto_init_by_seq::CryptoInitBySeq, crypto_init_by_sign_seq::CryptoInitBySignSeq,
    diffie_hellman::DiffieHellman, digest_length::DigestLength, error::Error, hash::Hash,
    hmac::Hmac, init_method_type::InitMethodType, init_params::InitParams, kdf_tree::KdfInput,
    kdf_tree::KdfTree, kdf_tree::KdfTreeR, key_container::ContainerProperty,
    key_container::KeyContainer, library::Library, password::Password, random::Random,
    sequence_checker::SequenceChecker, signanture::Signanture, signanture::Signature,
    symmetric::Symmetric, symmetric::SymmetricMode,
};

fn library() -> Library {
    let path = std::env::var_os("ALDCRYPTO_LIBRARY").expect("Set ALDCRYPTO_LIBRARY");
    // БЕЗОПАСНОСТЬ: явный запуск тестов подразумевает доверие плагину и его ABI.
    unsafe { Library::load(path).unwrap() }
}
fn context() -> BaseCrypt {
    let library = library();
    for _ in 0..16 {
        let mut bytes = vec![0; 64];
        getrandom::fill(&mut bytes).unwrap();
        match BaseCrypt::new(&library, CryptoInitBySeq::new(bytes)) {
            Ok(ctx) => return ctx,
            Err(Error::Native { code: 17 | 506, .. }) => continue,
            Err(e) => panic!("{e}"),
        }
    }
    panic!("Plugin rejected 16 fresh initialization sequences")
}
fn password() -> Password {
    Password::new("Wrapper-tests-2026!").unwrap()
}
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn inputs_are_checked_without_a_plugin() {
    assert!(matches!(
        Password::new("bad\0password"),
        Err(Error::InvalidInput(_))
    ));
    assert!(Password::new("пароль🔑").is_ok());
    assert!(matches!(
        unsafe { Library::load("relative.dll") },
        Err(Error::InvalidInput(_))
    ));
    assert_eq!(
        InitParams::from(CryptoInitBySeq::new(vec![1])).method(),
        InitMethodType::BySeq
    );
    assert_eq!(
        InitParams::from(CryptoInitByCont::new(vec![1], password())).method(),
        InitMethodType::Cont
    );
    assert_eq!(
        InitParams::from(CryptoInitBySignSeq::new(
            vec![1],
            vec![2],
            vec![3],
            password()
        ))
        .method(),
        InitMethodType::BySignSeq
    );
}

#[test]
#[ignore = "requires ALDCRYPTO_LIBRARY"]
fn random_and_sequence_checker() {
    let ctx = context();
    let mut random = Random::new(&ctx).unwrap();
    let mut checker = SequenceChecker::new(&ctx).unwrap();
    drop(ctx); // Оба дочерних объекта удерживают родителя и библиотеку.
    let first = random.generate(64).unwrap();
    let second = random.generate(64).unwrap();
    assert_ne!(first.as_slice(), second.as_slice());
    assert!(random.generate(usize::MAX).is_err());
    assert!(checker.check(&[0; 64]).is_err());
    let mut accepted = false;
    for _ in 0..16 {
        if checker.check(&random.generate(64).unwrap()).is_ok() {
            accepted = true;
            break;
        }
    }
    assert!(accepted, "Checker rejected all random samples");
}

#[test]
#[ignore = "requires ALDCRYPTO_LIBRARY"]
fn hash_and_hmac_vectors() {
    let ctx = context();
    let message = b"wrapper streaming test across chunks";
    for bits in [DigestLength::Bits256, DigestLength::Bits512] {
        let expected = Hash::compute_portable(&ctx, bits, message).unwrap();
        assert_eq!(
            Hash::new(&ctx, bits).unwrap().compute(message).unwrap(),
            expected
        );
        let mut stream = Hash::new(&ctx, bits).unwrap();
        for chunk in message.chunks(7) {
            stream.update(chunk).unwrap();
        }
        assert_eq!(stream.finalize().unwrap(), expected);
        let mut key: Vec<u8> = (0..32).collect();
        if bits == DigestLength::Bits512 {
            key.resize(64, 0);
        }
        let input = hex("0126bdb87800af214341456563780100");
        let expected = hex(if bits == DigestLength::Bits256 {
            "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9"
        } else {
            "a59bab22ecae19c65fbde6e5f4e9f5d8549d31f037f9df9b905500e171923a773d5f1530f2ed7e964cb2eedc29e9ad2f3afe93b2814f79f5000ffc0366c251e6"
        });
        let mut hmac = Hmac::with_key(&ctx, bits, &key).unwrap();
        assert_eq!(hmac.data().unwrap().hmacLen as usize, bits.bytes());
        assert_eq!(hmac.compute(&input).unwrap(), expected);
        let mut stream = Hmac::new(&ctx, bits).unwrap();
        stream.set_key(&key).unwrap();
        for chunk in input.chunks(3) {
            stream.update(chunk).unwrap();
        }
        assert_eq!(stream.finalize().unwrap(), expected);
        assert!(ctx.hmac_key_sizes(bits).unwrap().maxKeySize as usize >= key.len());
    }
}

#[test]
#[ignore = "requires ALDCRYPTO_LIBRARY"]
fn symmetric_modes_and_owned_buffer() {
    let ctx = context();
    let key = hex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
    let input = hex("1122334455667700ffeeddccbbaa9988");
    for mode in [SymmetricMode::Ecb, SymmetricMode::Cbc] {
        let mut cipher = Symmetric::new(&ctx, mode).unwrap();
        cipher.set_key(&key).unwrap();
        let iv = vec![0; cipher.data().unwrap().ivSize as usize];
        let encrypted = cipher.encrypt(&input, &iv).unwrap();
        if mode == SymmetricMode::Ecb {
            assert_eq!(encrypted, hex("7f679d90bebc24305a468d42b9d4edcd"));
        }
        assert_eq!(cipher.decrypt(&encrypted, &iv).unwrap(), input);
        assert!(cipher.encrypt(b"short", &iv).is_err());
    }
    match Symmetric::new(&ctx, SymmetricMode::Cfb) {
        Ok(mut cfb) => {
            cfb.set_key(&key).unwrap();
            let iv = vec![0; cfb.data().unwrap().ivSize as usize];
            let encrypted = cfb.encrypt(&input, &iv).unwrap();
            assert_eq!(cfb.decrypt(&encrypted, &iv).unwrap(), input);
        }
        Err(Error::Native { code: 2, .. }) => (), // Эта DLL не поддерживает CFB.
        Err(e) => panic!("Unexpected CFB error: {e}"),
    }
    let mut mac = Symmetric::new(&ctx, SymmetricMode::Omac).unwrap();
    mac.set_key(&key).unwrap();
    let iv = vec![0; mac.data().unwrap().ivSize as usize];
    assert_eq!(mac.encrypt(&input, &iv).unwrap().len(), 16);
    assert!(mac.decrypt(&input, &iv).is_err());
    let mut cipher = Symmetric::new(&ctx, SymmetricMode::Ecb).unwrap();
    cipher.set_key(&key).unwrap();
    let buffer = cipher.key().unwrap();
    drop(cipher);
    drop(mac);
    drop(ctx);
    assert_eq!(&*buffer, key); // Буфер сохраняет собственную ссылку на родителя и библиотеку.
}

#[test]
#[ignore = "requires ALDCRYPTO_LIBRARY"]
fn symmetric_key_containers() {
    let mut ctx = context();
    let pass = password();
    let mut key = Symmetric::new(&ctx, SymmetricMode::Ecb).unwrap();
    key.set_key(&[7; 32]).unwrap();
    let mut restored = Symmetric::new(&ctx, SymmetricMode::Ecb).unwrap();
    let blob = key.export_by_password(&pass).unwrap();
    restored.import_by_password(&blob, &pass).unwrap();
    assert_eq!(&*restored.key().unwrap(), &[7; 32]);
    assert!(
        restored
            .import_by_password(&blob, &Password::new("wrong").unwrap())
            .is_err()
    );
    let mut protector = Symmetric::new(&ctx, SymmetricMode::Cbc).unwrap();
    protector.set_key(&[9; 32]).unwrap();
    let blob = key.export_by_sym_key(&mut protector).unwrap();
    restored.import_by_sym_key(&blob, &mut protector).unwrap();
    assert_eq!(&*restored.key().unwrap(), &[7; 32]);
    let kkp = ctx.create_kkp(&pass).unwrap();
    let mut asymmetric = Asymmetric::new(&ctx).unwrap();
    asymmetric.import_by_password(&kkp, &pass).unwrap();
    let blob = key.export_by_asymmetric(&mut asymmetric).unwrap();
    restored
        .import_by_asymmetric(&blob, &mut asymmetric)
        .unwrap();
    assert_eq!(&*restored.key().unwrap(), &[7; 32]);
    let derived = Symmetric::from_password(&ctx, b"test password", &[1; 32]).unwrap();
    assert!(!derived.key().unwrap().is_empty());
}

#[test]
#[ignore = "requires ALDCRYPTO_LIBRARY"]
fn kdf_all_interfaces_and_context_validation() {
    let ctx = context();
    let key: Vec<u8> = (0..32).collect();
    let mut sym = Symmetric::new(&ctx, SymmetricMode::Ecb).unwrap();
    sym.set_key(&key).unwrap();
    let mut kdf = KdfTree::new(&ctx).unwrap();
    let label = hex("26bdb878");
    let seed = hex("af21434145656378");
    for r in [KdfTreeR::R1, KdfTreeR::R2, KdfTreeR::R4] {
        for len in [1, 33, 64] {
            let input = KdfInput {
                r,
                label: &label,
                seed: &seed,
                output_len: len,
            };
            let expected = KdfTree::derive_portable(&ctx, &key, &input).unwrap();
            assert_eq!(*kdf.derive(&key, &input).unwrap(), *expected);
            assert_eq!(*kdf.derive_by_sym_key(&sym, &input).unwrap(), *expected);
            assert_eq!(
                *KdfTree::derive_by_sym_key_portable(&ctx, &sym, &input).unwrap(),
                *expected
            );
            if r == KdfTreeR::R1 && len == 64 {
                assert_eq!(
                    *expected,
                    hex(
                        "22b6837845c6bef65ea71672b265831086d3c76aebe6dae91cad51d83f79d16b074c9330599d7f8d712fca54392f4ddde93751206b3584c8f43f9e6dc51531f9"
                    )
                );
            }
        }
        assert_eq!(KdfTree::data(&ctx, r).unwrap().r, r as u32);
    }
    let input = KdfInput {
        r: KdfTreeR::R1,
        label: &label,
        seed: &seed,
        output_len: 32,
    };
    assert!(kdf.derive(&[0; 31], &input).is_err());
    assert!(
        kdf.derive(
            &key,
            &KdfInput {
                output_len: 8161,
                ..input
            }
        )
        .is_err()
    );
    let other = context();
    let other_key = Symmetric::new(&other, SymmetricMode::Ecb).unwrap();
    assert!(matches!(
        kdf.derive_by_sym_key(&other_key, &input),
        Err(Error::InvalidInput(_))
    ));
}

#[test]
#[ignore = "requires ALDCRYPTO_LIBRARY"]
fn asymmetric_encryption_and_key_import() {
    let mut ctx = context();
    let pass = password();
    let kkp = ctx.create_kkp(&pass).unwrap();
    let mut receiver = Asymmetric::new(&ctx).unwrap();
    receiver.import_by_password(&kkp, &pass).unwrap();
    let mut sender = Asymmetric::new(&ctx).unwrap();
    let sender_key = ctx.create_kkp(&pass).unwrap();
    sender.import_by_password(&sender_key, &pass).unwrap();
    receiver
        .import_public(&sender.export_public(true).unwrap())
        .unwrap();
    sender
        .import_public(&receiver.export_public(true).unwrap())
        .unwrap();
    let plain = b"asymmetric wrapper test";
    let encrypted = sender.encrypt(plain).unwrap();
    assert_eq!(&*receiver.decrypt(&encrypted).unwrap(), plain);
    let exported = receiver.export_by_password(&pass).unwrap();
    let mut restored = Asymmetric::new(&ctx).unwrap();
    restored.import_by_password(&exported, &pass).unwrap();
    assert_eq!(&*restored.decrypt(&encrypted).unwrap(), plain);
}

#[test]
#[ignore = "requires ALDCRYPTO_LIBRARY"]
fn signature_verification_and_container_init() {
    let mut ctx = context();
    let pass = password();
    let kkp = ctx.create_kkp(&pass).unwrap();
    let mut signer = Signanture::new(&ctx).unwrap();
    signer.import_by_password(&kkp, &pass).unwrap();
    let message = b"signed wrapper test";
    let signature = signer.sign(message).unwrap();
    let mut verifier = Signature::new(&ctx).unwrap();
    verifier
        .import_public(&signer.export_public(true).unwrap(), true)
        .unwrap();
    verifier.verify(message, &signature).unwrap();
    assert!(
        verifier
            .verify(b"tampered wrapper test", &signature)
            .is_err()
    );
    let exported = signer.export_by_password(&pass).unwrap();
    let mut restored = Signature::new(&ctx).unwrap();
    restored.import_by_password(&exported, &pass).unwrap();
    restored.verify(message, &signature).unwrap();
    let library = library();
    let by_cont =
        BaseCrypt::new(&library, CryptoInitByCont::new(kkp.to_vec(), password())).unwrap();
    assert!(
        !Random::new(&by_cont)
            .unwrap()
            .generate(32)
            .unwrap()
            .is_empty()
    );
    let mut seed = vec![0; 64];
    getrandom::fill(&mut seed).unwrap();
    let signature = signer.sign(&seed).unwrap();
    let by_signed = BaseCrypt::new(
        &library,
        CryptoInitBySignSeq::new(seed, kkp.to_vec(), signature.to_vec(), password()),
    )
    .unwrap();
    assert!(
        !Random::new(&by_signed)
            .unwrap()
            .generate(32)
            .unwrap()
            .is_empty()
    );
    assert!(
        BaseCrypt::new(
            &library,
            CryptoInitByCont::new(kkp.to_vec(), Password::new("wrong").unwrap())
        )
        .is_err()
    );
}

#[test]
#[ignore = "requires ALDCRYPTO_LIBRARY"]
fn key_container_properties() {
    let mut ctx = context();
    let kkp = ctx.create_kkp(&password()).unwrap();
    let container = KeyContainer::from_bytes(&ctx, &kkp).unwrap();
    assert!(
        !container
            .property(ContainerProperty::PublicKey)
            .unwrap()
            .is_empty()
    );
    let guid = container.guid().unwrap();
    assert_ne!(guid, [0; 16]);
    let _period = container.expiration_period().unwrap();
    drop(kkp);
    drop(ctx);
    assert_eq!(container.guid().unwrap(), guid);
}

#[test]
#[ignore = "requires ALDCRYPTO_LIBRARY"]
fn diffie_hellman_keys_and_invalid_protocol_input() {
    let mut ctx = context();
    let pass = password();
    let alice_key = ctx.create_kkp(&pass).unwrap();
    let bob_key = ctx.create_kkp(&pass).unwrap();
    let mut alice = DiffieHellman::new(&ctx).unwrap();
    alice.import_by_password(&alice_key, &pass).unwrap();
    let mut bob = DiffieHellman::new(&ctx).unwrap();
    bob.import_by_password(&bob_key, &pass).unwrap();
    let alice_public = alice.export_public(true).unwrap();
    let bob_public = bob.export_public(true).unwrap();
    alice.import_public(&bob_public, true).unwrap();
    bob.import_public(&alice_public, true).unwrap();
    let exported = alice.export_by_password(&pass).unwrap();
    let mut restored = DiffieHellman::new(&ctx).unwrap();
    restored.import_by_password(&exported, &pass).unwrap();
    let private = alice.private_params().unwrap();
    restored.set_private_params(&private).unwrap();
    bob.set_private_params(&private).unwrap();
    // Заголовки не задают кодирование начального сообщения «Эхинацеи». Проверяем
    // передачу ошибки для неверного сообщения без предположений о формате протокола.
    assert!(matches!(
        alice.derive_step(&[]),
        Err(Error::Native { code: 3, .. })
    ));
    assert!(alice.export_derived_by_password(&pass).is_err());
}

#[test]
#[ignore = "requires ALDCRYPTO_LIBRARY"]
fn bio_random_keyboard() {
    let library = library();
    let flags = BioRandFlags { save_time: true };
    let mut bio = BioRandKb::new(&library, BioRandFlags::default()).unwrap();
    drop(library);
    for _ in 0..128 {
        let symbol = bio.generate_symbol(BioRandFlags::default()).unwrap();
        match bio.add_symbol(symbol, flags) {
            Ok(_)
            | Err(Error::Native {
                code: crypto::SharedErrors_Errors_time,
                ..
            }) => (),
            Err(e) => panic!("Unexpected keyboard generator error: {e}"),
        }
    }
    let result = bio.generate_result(BioRandFlags::default()).unwrap();
    drop(bio);
    assert!(!result.is_empty());
}
