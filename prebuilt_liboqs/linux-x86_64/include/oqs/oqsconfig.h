// SPDX-License-Identifier: MIT

/** 
 * Version of liboqs as a string. Equivalent to {MAJOR}.{MINOR}.{PATCH}{PRE_RELEASE} 
 */
#define OQS_VERSION_TEXT "0.14.1-dev"
/** 
 * Version levels of liboqs as integers.
 */
#define OQS_VERSION_MAJOR 0
#define OQS_VERSION_MINOR 14
#define OQS_VERSION_PATCH 1
/** 
 * OQS_VERSION_PRE_RELEASE is defined if this is a pre-release version of liboqs, otherwise it is undefined.
 * Examples: "-dev" or "-rc1".
 */
#define OQS_VERSION_PRE_RELEASE "-dev"

#define OQS_COMPILE_BUILD_TARGET "x86_64-Linux-5.15.167.4-microsoft-standard-WSL2"
#define OQS_DIST_BUILD 1
#define OQS_DIST_X86_64_BUILD 1
/* #undef OQS_DIST_X86_BUILD */
/* #undef OQS_DIST_ARM64_V8_BUILD */
/* #undef OQS_DIST_ARM32_V7_BUILD */
/* #undef OQS_DIST_PPC64LE_BUILD */
/* #undef OQS_DEBUG_BUILD */
#define ARCH_X86_64 1
/* #undef ARCH_ARM64v8 */
/* #undef ARCH_ARM32v7 */
#define BUILD_SHARED_LIBS 1
/* #undef OQS_BUILD_ONLY_LIB */
#define OQS_OPT_TARGET "generic"
/* #undef USE_COVERAGE */
/* #undef USE_SANITIZER */
/* #undef CMAKE_BUILD_TYPE */

#define OQS_USE_OPENSSL 1
/* #undef OQS_USE_AES_OPENSSL */
#define OQS_USE_SHA2_OPENSSL 1
/* #undef OQS_USE_SHA3_OPENSSL */
/* #undef OQS_DLOPEN_OPENSSL */
/* #undef OQS_OPENSSL_CRYPTO_SONAME */

/* #undef OQS_EMBEDDED_BUILD */

#define OQS_USE_PTHREADS 1

/* #undef OQS_USE_ADX_INSTRUCTIONS */
/* #undef OQS_USE_AES_INSTRUCTIONS */
/* #undef OQS_USE_AVX_INSTRUCTIONS */
/* #undef OQS_USE_AVX2_INSTRUCTIONS */
/* #undef OQS_USE_AVX512_INSTRUCTIONS */
/* #undef OQS_USE_BMI1_INSTRUCTIONS */
/* #undef OQS_USE_BMI2_INSTRUCTIONS */
/* #undef OQS_USE_PCLMULQDQ_INSTRUCTIONS */
/* #undef OQS_USE_VPCLMULQDQ_INSTRUCTIONS */
/* #undef OQS_USE_POPCNT_INSTRUCTIONS */
/* #undef OQS_USE_SSE_INSTRUCTIONS */
/* #undef OQS_USE_SSE2_INSTRUCTIONS */
/* #undef OQS_USE_SSE3_INSTRUCTIONS */

/* #undef OQS_USE_ARM_AES_INSTRUCTIONS */
/* #undef OQS_USE_ARM_SHA2_INSTRUCTIONS */
/* #undef OQS_USE_ARM_SHA3_INSTRUCTIONS */
/* #undef OQS_USE_ARM_NEON_INSTRUCTIONS */

/* #undef OQS_SPEED_USE_ARM_PMU */

/* #undef OQS_ENABLE_TEST_CONSTANT_TIME */

#define OQS_ENABLE_SHA3_xkcp_low_avx2 1
#define OQS_USE_SHA3_AVX512VL 1

#define OQS_USE_CUPQC 0
#define OQS_USE_ICICLE 0

#define OQS_ENABLE_KEM_BIKE 1
#define OQS_ENABLE_KEM_bike_l1 1
#define OQS_ENABLE_KEM_bike_l3 1
#define OQS_ENABLE_KEM_bike_l5 1

#define OQS_ENABLE_KEM_FRODOKEM 1
#define OQS_ENABLE_KEM_frodokem_640_aes 1
#define OQS_ENABLE_KEM_frodokem_640_shake 1
#define OQS_ENABLE_KEM_frodokem_976_aes 1
#define OQS_ENABLE_KEM_frodokem_976_shake 1
#define OQS_ENABLE_KEM_frodokem_1344_aes 1
#define OQS_ENABLE_KEM_frodokem_1344_shake 1

#define OQS_ENABLE_KEM_NTRUPRIME 1
#define OQS_ENABLE_KEM_ntruprime_sntrup761 1
#define OQS_ENABLE_KEM_ntruprime_sntrup761_avx2 1

#define OQS_ENABLE_KEM_NTRU 1
#define OQS_ENABLE_KEM_ntru_hps2048509 1
#define OQS_ENABLE_KEM_ntru_hps2048509_avx2 1
#define OQS_ENABLE_KEM_ntru_hps2048677 1
#define OQS_ENABLE_KEM_ntru_hps2048677_avx2 1
#define OQS_ENABLE_KEM_ntru_hps4096821 1
#define OQS_ENABLE_KEM_ntru_hps4096821_avx2 1
#define OQS_ENABLE_KEM_ntru_hps40961229 1
#define OQS_ENABLE_KEM_ntru_hrss701 1
#define OQS_ENABLE_KEM_ntru_hrss701_avx2 1
#define OQS_ENABLE_KEM_ntru_hrss1373 1

///// OQS_COPY_FROM_UPSTREAM_FRAGMENT_ADD_ALG_ENABLE_DEFINES_START

#define OQS_ENABLE_KEM_CLASSIC_MCELIECE 1
#define OQS_ENABLE_KEM_classic_mceliece_348864 1
#define OQS_ENABLE_KEM_classic_mceliece_348864_avx2 1
#define OQS_ENABLE_KEM_classic_mceliece_348864f 1
#define OQS_ENABLE_KEM_classic_mceliece_348864f_avx2 1
#define OQS_ENABLE_KEM_classic_mceliece_460896 1
#define OQS_ENABLE_KEM_classic_mceliece_460896_avx2 1
#define OQS_ENABLE_KEM_classic_mceliece_460896f 1
#define OQS_ENABLE_KEM_classic_mceliece_460896f_avx2 1
#define OQS_ENABLE_KEM_classic_mceliece_6688128 1
#define OQS_ENABLE_KEM_classic_mceliece_6688128_avx2 1
#define OQS_ENABLE_KEM_classic_mceliece_6688128f 1
#define OQS_ENABLE_KEM_classic_mceliece_6688128f_avx2 1
#define OQS_ENABLE_KEM_classic_mceliece_6960119 1
#define OQS_ENABLE_KEM_classic_mceliece_6960119_avx2 1
#define OQS_ENABLE_KEM_classic_mceliece_6960119f 1
#define OQS_ENABLE_KEM_classic_mceliece_6960119f_avx2 1
#define OQS_ENABLE_KEM_classic_mceliece_8192128 1
#define OQS_ENABLE_KEM_classic_mceliece_8192128_avx2 1
#define OQS_ENABLE_KEM_classic_mceliece_8192128f 1
#define OQS_ENABLE_KEM_classic_mceliece_8192128f_avx2 1

/* #undef OQS_ENABLE_KEM_HQC */
/* #undef OQS_ENABLE_KEM_hqc_128 */
/* #undef OQS_ENABLE_KEM_hqc_192 */
/* #undef OQS_ENABLE_KEM_hqc_256 */

#define OQS_ENABLE_KEM_KYBER 1
#define OQS_ENABLE_KEM_kyber_512 1
#define OQS_ENABLE_KEM_kyber_512_avx2 1
/* #undef OQS_ENABLE_KEM_kyber_512_aarch64 */
#define OQS_ENABLE_KEM_kyber_768 1
#define OQS_ENABLE_KEM_kyber_768_avx2 1
/* #undef OQS_ENABLE_KEM_kyber_768_aarch64 */
#define OQS_ENABLE_KEM_kyber_1024 1
#define OQS_ENABLE_KEM_kyber_1024_avx2 1
/* #undef OQS_ENABLE_KEM_kyber_1024_aarch64 */

#define OQS_ENABLE_KEM_ML_KEM 1
#define OQS_ENABLE_KEM_ml_kem_512 1
#define OQS_ENABLE_KEM_ml_kem_512_x86_64 1
/* #undef OQS_ENABLE_KEM_ml_kem_512_aarch64 */
/* #undef OQS_ENABLE_KEM_ml_kem_512_cuda */
/* #undef OQS_ENABLE_KEM_ml_kem_512_icicle_cuda */
#define OQS_ENABLE_KEM_ml_kem_768 1
#define OQS_ENABLE_KEM_ml_kem_768_x86_64 1
/* #undef OQS_ENABLE_KEM_ml_kem_768_aarch64 */
/* #undef OQS_ENABLE_KEM_ml_kem_768_cuda */
/* #undef OQS_ENABLE_KEM_ml_kem_768_icicle_cuda */
#define OQS_ENABLE_KEM_ml_kem_1024 1
#define OQS_ENABLE_KEM_ml_kem_1024_x86_64 1
/* #undef OQS_ENABLE_KEM_ml_kem_1024_aarch64 */
/* #undef OQS_ENABLE_KEM_ml_kem_1024_cuda */
/* #undef OQS_ENABLE_KEM_ml_kem_1024_icicle_cuda */

#define OQS_ENABLE_SIG_ML_DSA 1
#define OQS_ENABLE_SIG_ml_dsa_44 1
#define OQS_ENABLE_SIG_ml_dsa_44_avx2 1
#define OQS_ENABLE_SIG_ml_dsa_65 1
#define OQS_ENABLE_SIG_ml_dsa_65_avx2 1
#define OQS_ENABLE_SIG_ml_dsa_87 1
#define OQS_ENABLE_SIG_ml_dsa_87_avx2 1

#define OQS_ENABLE_SIG_FALCON 1
#define OQS_ENABLE_SIG_falcon_512 1
#define OQS_ENABLE_SIG_falcon_512_avx2 1
/* #undef OQS_ENABLE_SIG_falcon_512_aarch64 */
#define OQS_ENABLE_SIG_falcon_1024 1
#define OQS_ENABLE_SIG_falcon_1024_avx2 1
/* #undef OQS_ENABLE_SIG_falcon_1024_aarch64 */
#define OQS_ENABLE_SIG_falcon_padded_512 1
#define OQS_ENABLE_SIG_falcon_padded_512_avx2 1
/* #undef OQS_ENABLE_SIG_falcon_padded_512_aarch64 */
#define OQS_ENABLE_SIG_falcon_padded_1024 1
#define OQS_ENABLE_SIG_falcon_padded_1024_avx2 1
/* #undef OQS_ENABLE_SIG_falcon_padded_1024_aarch64 */

#define OQS_ENABLE_SIG_SPHINCS 1
#define OQS_ENABLE_SIG_sphincs_sha2_128f_simple 1
#define OQS_ENABLE_SIG_sphincs_sha2_128f_simple_avx2 1
#define OQS_ENABLE_SIG_sphincs_sha2_128s_simple 1
#define OQS_ENABLE_SIG_sphincs_sha2_128s_simple_avx2 1
#define OQS_ENABLE_SIG_sphincs_sha2_192f_simple 1
#define OQS_ENABLE_SIG_sphincs_sha2_192f_simple_avx2 1
#define OQS_ENABLE_SIG_sphincs_sha2_192s_simple 1
#define OQS_ENABLE_SIG_sphincs_sha2_192s_simple_avx2 1
#define OQS_ENABLE_SIG_sphincs_sha2_256f_simple 1
#define OQS_ENABLE_SIG_sphincs_sha2_256f_simple_avx2 1
#define OQS_ENABLE_SIG_sphincs_sha2_256s_simple 1
#define OQS_ENABLE_SIG_sphincs_sha2_256s_simple_avx2 1
#define OQS_ENABLE_SIG_sphincs_shake_128f_simple 1
#define OQS_ENABLE_SIG_sphincs_shake_128f_simple_avx2 1
#define OQS_ENABLE_SIG_sphincs_shake_128s_simple 1
#define OQS_ENABLE_SIG_sphincs_shake_128s_simple_avx2 1
#define OQS_ENABLE_SIG_sphincs_shake_192f_simple 1
#define OQS_ENABLE_SIG_sphincs_shake_192f_simple_avx2 1
#define OQS_ENABLE_SIG_sphincs_shake_192s_simple 1
#define OQS_ENABLE_SIG_sphincs_shake_192s_simple_avx2 1
#define OQS_ENABLE_SIG_sphincs_shake_256f_simple 1
#define OQS_ENABLE_SIG_sphincs_shake_256f_simple_avx2 1
#define OQS_ENABLE_SIG_sphincs_shake_256s_simple 1
#define OQS_ENABLE_SIG_sphincs_shake_256s_simple_avx2 1

#define OQS_ENABLE_SIG_MAYO 1
#define OQS_ENABLE_SIG_mayo_1 1
#define OQS_ENABLE_SIG_mayo_1_avx2 1
/* #undef OQS_ENABLE_SIG_mayo_1_neon */
#define OQS_ENABLE_SIG_mayo_2 1
#define OQS_ENABLE_SIG_mayo_2_avx2 1
/* #undef OQS_ENABLE_SIG_mayo_2_neon */
#define OQS_ENABLE_SIG_mayo_3 1
#define OQS_ENABLE_SIG_mayo_3_avx2 1
/* #undef OQS_ENABLE_SIG_mayo_3_neon */
#define OQS_ENABLE_SIG_mayo_5 1
#define OQS_ENABLE_SIG_mayo_5_avx2 1
/* #undef OQS_ENABLE_SIG_mayo_5_neon */

#define OQS_ENABLE_SIG_CROSS 1
#define OQS_ENABLE_SIG_cross_rsdp_128_balanced 1
#define OQS_ENABLE_SIG_cross_rsdp_128_balanced_avx2 1
#define OQS_ENABLE_SIG_cross_rsdp_128_fast 1
#define OQS_ENABLE_SIG_cross_rsdp_128_fast_avx2 1
#define OQS_ENABLE_SIG_cross_rsdp_128_small 1
#define OQS_ENABLE_SIG_cross_rsdp_128_small_avx2 1
#define OQS_ENABLE_SIG_cross_rsdp_192_balanced 1
#define OQS_ENABLE_SIG_cross_rsdp_192_balanced_avx2 1
#define OQS_ENABLE_SIG_cross_rsdp_192_fast 1
#define OQS_ENABLE_SIG_cross_rsdp_192_fast_avx2 1
#define OQS_ENABLE_SIG_cross_rsdp_192_small 1
#define OQS_ENABLE_SIG_cross_rsdp_192_small_avx2 1
#define OQS_ENABLE_SIG_cross_rsdp_256_balanced 1
#define OQS_ENABLE_SIG_cross_rsdp_256_balanced_avx2 1
#define OQS_ENABLE_SIG_cross_rsdp_256_fast 1
#define OQS_ENABLE_SIG_cross_rsdp_256_fast_avx2 1
#define OQS_ENABLE_SIG_cross_rsdp_256_small 1
#define OQS_ENABLE_SIG_cross_rsdp_256_small_avx2 1
#define OQS_ENABLE_SIG_cross_rsdpg_128_balanced 1
#define OQS_ENABLE_SIG_cross_rsdpg_128_balanced_avx2 1
#define OQS_ENABLE_SIG_cross_rsdpg_128_fast 1
#define OQS_ENABLE_SIG_cross_rsdpg_128_fast_avx2 1
#define OQS_ENABLE_SIG_cross_rsdpg_128_small 1
#define OQS_ENABLE_SIG_cross_rsdpg_128_small_avx2 1
#define OQS_ENABLE_SIG_cross_rsdpg_192_balanced 1
#define OQS_ENABLE_SIG_cross_rsdpg_192_balanced_avx2 1
#define OQS_ENABLE_SIG_cross_rsdpg_192_fast 1
#define OQS_ENABLE_SIG_cross_rsdpg_192_fast_avx2 1
#define OQS_ENABLE_SIG_cross_rsdpg_192_small 1
#define OQS_ENABLE_SIG_cross_rsdpg_192_small_avx2 1
#define OQS_ENABLE_SIG_cross_rsdpg_256_balanced 1
#define OQS_ENABLE_SIG_cross_rsdpg_256_balanced_avx2 1
#define OQS_ENABLE_SIG_cross_rsdpg_256_fast 1
#define OQS_ENABLE_SIG_cross_rsdpg_256_fast_avx2 1
#define OQS_ENABLE_SIG_cross_rsdpg_256_small 1
#define OQS_ENABLE_SIG_cross_rsdpg_256_small_avx2 1

#define OQS_ENABLE_SIG_UOV 1
#define OQS_ENABLE_SIG_uov_ov_Is 1
/* #undef OQS_ENABLE_SIG_uov_ov_Is_neon */
#define OQS_ENABLE_SIG_uov_ov_Is_avx2 1
#define OQS_ENABLE_SIG_uov_ov_Ip 1
/* #undef OQS_ENABLE_SIG_uov_ov_Ip_neon */
#define OQS_ENABLE_SIG_uov_ov_Ip_avx2 1
#define OQS_ENABLE_SIG_uov_ov_III 1
/* #undef OQS_ENABLE_SIG_uov_ov_III_neon */
#define OQS_ENABLE_SIG_uov_ov_III_avx2 1
#define OQS_ENABLE_SIG_uov_ov_V 1
/* #undef OQS_ENABLE_SIG_uov_ov_V_neon */
#define OQS_ENABLE_SIG_uov_ov_V_avx2 1
#define OQS_ENABLE_SIG_uov_ov_Is_pkc 1
/* #undef OQS_ENABLE_SIG_uov_ov_Is_pkc_neon */
#define OQS_ENABLE_SIG_uov_ov_Is_pkc_avx2 1
#define OQS_ENABLE_SIG_uov_ov_Ip_pkc 1
/* #undef OQS_ENABLE_SIG_uov_ov_Ip_pkc_neon */
#define OQS_ENABLE_SIG_uov_ov_Ip_pkc_avx2 1
#define OQS_ENABLE_SIG_uov_ov_III_pkc 1
/* #undef OQS_ENABLE_SIG_uov_ov_III_pkc_neon */
#define OQS_ENABLE_SIG_uov_ov_III_pkc_avx2 1
#define OQS_ENABLE_SIG_uov_ov_V_pkc 1
/* #undef OQS_ENABLE_SIG_uov_ov_V_pkc_neon */
#define OQS_ENABLE_SIG_uov_ov_V_pkc_avx2 1
#define OQS_ENABLE_SIG_uov_ov_Is_pkc_skc 1
/* #undef OQS_ENABLE_SIG_uov_ov_Is_pkc_skc_neon */
#define OQS_ENABLE_SIG_uov_ov_Is_pkc_skc_avx2 1
#define OQS_ENABLE_SIG_uov_ov_Ip_pkc_skc 1
/* #undef OQS_ENABLE_SIG_uov_ov_Ip_pkc_skc_neon */
#define OQS_ENABLE_SIG_uov_ov_Ip_pkc_skc_avx2 1
#define OQS_ENABLE_SIG_uov_ov_III_pkc_skc 1
/* #undef OQS_ENABLE_SIG_uov_ov_III_pkc_skc_neon */
#define OQS_ENABLE_SIG_uov_ov_III_pkc_skc_avx2 1
#define OQS_ENABLE_SIG_uov_ov_V_pkc_skc 1
/* #undef OQS_ENABLE_SIG_uov_ov_V_pkc_skc_neon */
#define OQS_ENABLE_SIG_uov_ov_V_pkc_skc_avx2 1

#define OQS_ENABLE_SIG_SNOVA 1
#define OQS_ENABLE_SIG_snova_SNOVA_24_5_4 1
#define OQS_ENABLE_SIG_snova_SNOVA_24_5_4_avx2 1
/* #undef OQS_ENABLE_SIG_snova_SNOVA_24_5_4_neon */
#define OQS_ENABLE_SIG_snova_SNOVA_24_5_4_SHAKE 1
#define OQS_ENABLE_SIG_snova_SNOVA_24_5_4_SHAKE_avx2 1
/* #undef OQS_ENABLE_SIG_snova_SNOVA_24_5_4_SHAKE_neon */
#define OQS_ENABLE_SIG_snova_SNOVA_24_5_4_esk 1
#define OQS_ENABLE_SIG_snova_SNOVA_24_5_4_esk_avx2 1
/* #undef OQS_ENABLE_SIG_snova_SNOVA_24_5_4_esk_neon */
#define OQS_ENABLE_SIG_snova_SNOVA_24_5_4_SHAKE_esk 1
#define OQS_ENABLE_SIG_snova_SNOVA_24_5_4_SHAKE_esk_avx2 1
/* #undef OQS_ENABLE_SIG_snova_SNOVA_24_5_4_SHAKE_esk_neon */
#define OQS_ENABLE_SIG_snova_SNOVA_37_17_2 1
#define OQS_ENABLE_SIG_snova_SNOVA_37_17_2_avx2 1
/* #undef OQS_ENABLE_SIG_snova_SNOVA_37_17_2_neon */
#define OQS_ENABLE_SIG_snova_SNOVA_25_8_3 1
#define OQS_ENABLE_SIG_snova_SNOVA_25_8_3_avx2 1
/* #undef OQS_ENABLE_SIG_snova_SNOVA_25_8_3_neon */
#define OQS_ENABLE_SIG_snova_SNOVA_56_25_2 1
#define OQS_ENABLE_SIG_snova_SNOVA_56_25_2_avx2 1
/* #undef OQS_ENABLE_SIG_snova_SNOVA_56_25_2_neon */
#define OQS_ENABLE_SIG_snova_SNOVA_49_11_3 1
#define OQS_ENABLE_SIG_snova_SNOVA_49_11_3_avx2 1
/* #undef OQS_ENABLE_SIG_snova_SNOVA_49_11_3_neon */
#define OQS_ENABLE_SIG_snova_SNOVA_37_8_4 1
#define OQS_ENABLE_SIG_snova_SNOVA_37_8_4_avx2 1
/* #undef OQS_ENABLE_SIG_snova_SNOVA_37_8_4_neon */
#define OQS_ENABLE_SIG_snova_SNOVA_24_5_5 1
#define OQS_ENABLE_SIG_snova_SNOVA_24_5_5_avx2 1
/* #undef OQS_ENABLE_SIG_snova_SNOVA_24_5_5_neon */
#define OQS_ENABLE_SIG_snova_SNOVA_60_10_4 1
#define OQS_ENABLE_SIG_snova_SNOVA_60_10_4_avx2 1
/* #undef OQS_ENABLE_SIG_snova_SNOVA_60_10_4_neon */
#define OQS_ENABLE_SIG_snova_SNOVA_29_6_5 1
#define OQS_ENABLE_SIG_snova_SNOVA_29_6_5_avx2 1
/* #undef OQS_ENABLE_SIG_snova_SNOVA_29_6_5_neon */
///// OQS_COPY_FROM_UPSTREAM_FRAGMENT_ADD_ALG_ENABLE_DEFINES_END
///// OQS_COPY_FROM_SLH_DSA_FRAGMENT_ADD_ALG_ENABLE_DEFINES_START
#define OQS_ENABLE_SIG_SLH_DSA 1
#define OQS_ENABLE_SIG_slh_dsa_pure_sha2_128s 1
#define OQS_ENABLE_SIG_slh_dsa_pure_sha2_128f 1
#define OQS_ENABLE_SIG_slh_dsa_pure_sha2_192s 1
#define OQS_ENABLE_SIG_slh_dsa_pure_sha2_192f 1
#define OQS_ENABLE_SIG_slh_dsa_pure_sha2_256s 1
#define OQS_ENABLE_SIG_slh_dsa_pure_sha2_256f 1
#define OQS_ENABLE_SIG_slh_dsa_pure_shake_128s 1
#define OQS_ENABLE_SIG_slh_dsa_pure_shake_128f 1
#define OQS_ENABLE_SIG_slh_dsa_pure_shake_192s 1
#define OQS_ENABLE_SIG_slh_dsa_pure_shake_192f 1
#define OQS_ENABLE_SIG_slh_dsa_pure_shake_256s 1
#define OQS_ENABLE_SIG_slh_dsa_pure_shake_256f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_224_prehash_sha2_128s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_224_prehash_sha2_128f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_224_prehash_sha2_192s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_224_prehash_sha2_192f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_224_prehash_sha2_256s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_224_prehash_sha2_256f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_224_prehash_shake_128s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_224_prehash_shake_128f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_224_prehash_shake_192s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_224_prehash_shake_192f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_224_prehash_shake_256s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_224_prehash_shake_256f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_256_prehash_sha2_128s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_256_prehash_sha2_128f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_256_prehash_sha2_192s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_256_prehash_sha2_192f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_256_prehash_sha2_256s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_256_prehash_sha2_256f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_256_prehash_shake_128s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_256_prehash_shake_128f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_256_prehash_shake_192s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_256_prehash_shake_192f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_256_prehash_shake_256s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_256_prehash_shake_256f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_384_prehash_sha2_128s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_384_prehash_sha2_128f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_384_prehash_sha2_192s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_384_prehash_sha2_192f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_384_prehash_sha2_256s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_384_prehash_sha2_256f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_384_prehash_shake_128s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_384_prehash_shake_128f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_384_prehash_shake_192s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_384_prehash_shake_192f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_384_prehash_shake_256s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_384_prehash_shake_256f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_prehash_sha2_128s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_prehash_sha2_128f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_prehash_sha2_192s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_prehash_sha2_192f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_prehash_sha2_256s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_prehash_sha2_256f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_prehash_shake_128s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_prehash_shake_128f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_prehash_shake_192s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_prehash_shake_192f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_prehash_shake_256s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_prehash_shake_256f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_224_prehash_sha2_128s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_224_prehash_sha2_128f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_224_prehash_sha2_192s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_224_prehash_sha2_192f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_224_prehash_sha2_256s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_224_prehash_sha2_256f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_224_prehash_shake_128s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_224_prehash_shake_128f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_224_prehash_shake_192s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_224_prehash_shake_192f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_224_prehash_shake_256s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_224_prehash_shake_256f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_256_prehash_sha2_128s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_256_prehash_sha2_128f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_256_prehash_sha2_192s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_256_prehash_sha2_192f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_256_prehash_sha2_256s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_256_prehash_sha2_256f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_256_prehash_shake_128s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_256_prehash_shake_128f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_256_prehash_shake_192s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_256_prehash_shake_192f 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_256_prehash_shake_256s 1
#define OQS_ENABLE_SIG_slh_dsa_sha2_512_256_prehash_shake_256f 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_224_prehash_sha2_128s 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_224_prehash_sha2_128f 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_224_prehash_sha2_192s 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_224_prehash_sha2_192f 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_224_prehash_sha2_256s 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_224_prehash_sha2_256f 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_224_prehash_shake_128s 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_224_prehash_shake_128f 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_224_prehash_shake_192s 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_224_prehash_shake_192f 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_224_prehash_shake_256s 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_224_prehash_shake_256f 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_256_prehash_sha2_128s 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_256_prehash_sha2_128f 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_256_prehash_sha2_192s 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_256_prehash_sha2_192f 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_256_prehash_sha2_256s 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_256_prehash_sha2_256f 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_256_prehash_shake_128s 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_256_prehash_shake_128f 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_256_prehash_shake_192s 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_256_prehash_shake_192f 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_256_prehash_shake_256s 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_256_prehash_shake_256f 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_384_prehash_sha2_128s 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_384_prehash_sha2_128f 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_384_prehash_sha2_192s 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_384_prehash_sha2_192f 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_384_prehash_sha2_256s 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_384_prehash_sha2_256f 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_384_prehash_shake_128s 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_384_prehash_shake_128f 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_384_prehash_shake_192s 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_384_prehash_shake_192f 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_384_prehash_shake_256s 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_384_prehash_shake_256f 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_512_prehash_sha2_128s 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_512_prehash_sha2_128f 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_512_prehash_sha2_192s 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_512_prehash_sha2_192f 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_512_prehash_sha2_256s 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_512_prehash_sha2_256f 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_512_prehash_shake_128s 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_512_prehash_shake_128f 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_512_prehash_shake_192s 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_512_prehash_shake_192f 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_512_prehash_shake_256s 1
#define OQS_ENABLE_SIG_slh_dsa_sha3_512_prehash_shake_256f 1
#define OQS_ENABLE_SIG_slh_dsa_shake_128_prehash_sha2_128s 1
#define OQS_ENABLE_SIG_slh_dsa_shake_128_prehash_sha2_128f 1
#define OQS_ENABLE_SIG_slh_dsa_shake_128_prehash_sha2_192s 1
#define OQS_ENABLE_SIG_slh_dsa_shake_128_prehash_sha2_192f 1
#define OQS_ENABLE_SIG_slh_dsa_shake_128_prehash_sha2_256s 1
#define OQS_ENABLE_SIG_slh_dsa_shake_128_prehash_sha2_256f 1
#define OQS_ENABLE_SIG_slh_dsa_shake_128_prehash_shake_128s 1
#define OQS_ENABLE_SIG_slh_dsa_shake_128_prehash_shake_128f 1
#define OQS_ENABLE_SIG_slh_dsa_shake_128_prehash_shake_192s 1
#define OQS_ENABLE_SIG_slh_dsa_shake_128_prehash_shake_192f 1
#define OQS_ENABLE_SIG_slh_dsa_shake_128_prehash_shake_256s 1
#define OQS_ENABLE_SIG_slh_dsa_shake_128_prehash_shake_256f 1
#define OQS_ENABLE_SIG_slh_dsa_shake_256_prehash_sha2_128s 1
#define OQS_ENABLE_SIG_slh_dsa_shake_256_prehash_sha2_128f 1
#define OQS_ENABLE_SIG_slh_dsa_shake_256_prehash_sha2_192s 1
#define OQS_ENABLE_SIG_slh_dsa_shake_256_prehash_sha2_192f 1
#define OQS_ENABLE_SIG_slh_dsa_shake_256_prehash_sha2_256s 1
#define OQS_ENABLE_SIG_slh_dsa_shake_256_prehash_sha2_256f 1
#define OQS_ENABLE_SIG_slh_dsa_shake_256_prehash_shake_128s 1
#define OQS_ENABLE_SIG_slh_dsa_shake_256_prehash_shake_128f 1
#define OQS_ENABLE_SIG_slh_dsa_shake_256_prehash_shake_192s 1
#define OQS_ENABLE_SIG_slh_dsa_shake_256_prehash_shake_192f 1
#define OQS_ENABLE_SIG_slh_dsa_shake_256_prehash_shake_256s 1
#define OQS_ENABLE_SIG_slh_dsa_shake_256_prehash_shake_256f 1
///// OQS_COPY_FROM_SLH_DSA_FRAGMENT_ADD_ALG_ENABLE_DEFINES_END

///// OQS_COPY_FROM_LIBJADE_FRAGMENT_ADD_ALG_ENABLE_DEFINES_START

#define OQS_LIBJADE_BUILD 0

/* #undef OQS_ENABLE_LIBJADE_KEM_KYBER */
/* #undef OQS_ENABLE_LIBJADE_KEM_kyber_512 */
/* #undef OQS_ENABLE_LIBJADE_KEM_kyber_512_avx2 */
/* #undef OQS_ENABLE_LIBJADE_KEM_kyber_768 */
/* #undef OQS_ENABLE_LIBJADE_KEM_kyber_768_avx2 */
///// OQS_COPY_FROM_LIBJADE_FRAGMENT_ADD_ALG_ENABLE_DEFINES_END

/* #undef OQS_ENABLE_SIG_STFL_XMSS */
/* #undef OQS_ENABLE_SIG_STFL_xmss_sha256_h10 */
/* #undef OQS_ENABLE_SIG_STFL_xmss_sha256_h16 */
/* #undef OQS_ENABLE_SIG_STFL_xmss_sha256_h20 */
/* #undef OQS_ENABLE_SIG_STFL_xmss_shake128_h10 */
/* #undef OQS_ENABLE_SIG_STFL_xmss_shake128_h16 */
/* #undef OQS_ENABLE_SIG_STFL_xmss_shake128_h20 */
/* #undef OQS_ENABLE_SIG_STFL_xmss_sha512_h10 */
/* #undef OQS_ENABLE_SIG_STFL_xmss_sha512_h16 */
/* #undef OQS_ENABLE_SIG_STFL_xmss_sha512_h20 */
/* #undef OQS_ENABLE_SIG_STFL_xmss_shake256_h10 */
/* #undef OQS_ENABLE_SIG_STFL_xmss_shake256_h16 */
/* #undef OQS_ENABLE_SIG_STFL_xmss_shake256_h20 */
/* #undef OQS_ENABLE_SIG_STFL_xmss_sha256_h10_192 */
/* #undef OQS_ENABLE_SIG_STFL_xmss_sha256_h16_192 */
/* #undef OQS_ENABLE_SIG_STFL_xmss_sha256_h20_192 */
/* #undef OQS_ENABLE_SIG_STFL_xmss_shake256_h10_192 */
/* #undef OQS_ENABLE_SIG_STFL_xmss_shake256_h16_192 */
/* #undef OQS_ENABLE_SIG_STFL_xmss_shake256_h20_192 */
/* #undef OQS_ENABLE_SIG_STFL_xmss_shake256_h10_256 */
/* #undef OQS_ENABLE_SIG_STFL_xmss_shake256_h16_256 */
/* #undef OQS_ENABLE_SIG_STFL_xmss_shake256_h20_256 */

/* #undef OQS_ENABLE_SIG_STFL_xmssmt_sha256_h20_2 */
/* #undef OQS_ENABLE_SIG_STFL_xmssmt_sha256_h20_4 */
/* #undef OQS_ENABLE_SIG_STFL_xmssmt_sha256_h40_2 */
/* #undef OQS_ENABLE_SIG_STFL_xmssmt_sha256_h40_4 */
/* #undef OQS_ENABLE_SIG_STFL_xmssmt_sha256_h40_8 */
/* #undef OQS_ENABLE_SIG_STFL_xmssmt_sha256_h60_3 */
/* #undef OQS_ENABLE_SIG_STFL_xmssmt_sha256_h60_6 */
/* #undef OQS_ENABLE_SIG_STFL_xmssmt_sha256_h60_12 */
/* #undef OQS_ENABLE_SIG_STFL_xmssmt_shake128_h20_2 */
/* #undef OQS_ENABLE_SIG_STFL_xmssmt_shake128_h20_4 */
/* #undef OQS_ENABLE_SIG_STFL_xmssmt_shake128_h40_2 */
/* #undef OQS_ENABLE_SIG_STFL_xmssmt_shake128_h40_4 */
/* #undef OQS_ENABLE_SIG_STFL_xmssmt_shake128_h40_8 */
/* #undef OQS_ENABLE_SIG_STFL_xmssmt_shake128_h60_3 */
/* #undef OQS_ENABLE_SIG_STFL_xmssmt_shake128_h60_6 */
/* #undef OQS_ENABLE_SIG_STFL_xmssmt_shake128_h60_12 */


/* #undef OQS_ENABLE_SIG_STFL_LMS */
/* #undef OQS_ENABLE_SIG_STFL_lms_sha256_h5_w1 */
/* #undef OQS_ENABLE_SIG_STFL_lms_sha256_h5_w2 */
/* #undef OQS_ENABLE_SIG_STFL_lms_sha256_h5_w4 */
/* #undef OQS_ENABLE_SIG_STFL_lms_sha256_h5_w8 */
/* #undef OQS_ENABLE_SIG_STFL_lms_sha256_h10_w1 */
/* #undef OQS_ENABLE_SIG_STFL_lms_sha256_h10_w2 */
/* #undef OQS_ENABLE_SIG_STFL_lms_sha256_h10_w4 */
/* #undef OQS_ENABLE_SIG_STFL_lms_sha256_h10_w8 */
/* #undef OQS_ENABLE_SIG_STFL_lms_sha256_h15_w1 */
/* #undef OQS_ENABLE_SIG_STFL_lms_sha256_h15_w2 */
/* #undef OQS_ENABLE_SIG_STFL_lms_sha256_h15_w4 */
/* #undef OQS_ENABLE_SIG_STFL_lms_sha256_h5_w8_h5_w8 */
/* #undef OQS_ENABLE_SIG_STFL_lms_sha256_h10_w4_h5_w8 */

/* #undef OQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN */
/* #undef OQS_ALLOW_STFL_KEY_AND_SIG_GEN */
/* #undef OQS_ALLOW_XMSS_KEY_AND_SIG_GEN */
/* #undef OQS_ALLOW_LMS_KEY_AND_SIG_GEN */
