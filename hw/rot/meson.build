# TomCrypt dependency

libtomcrypt_dep = subproject('libtomcrypt').get_variable('libtomcrypt_dep')

# OpenTitan devices

system_ss.add(when: 'CONFIG_OT_AES', if_true: [files('ot_aes.c'), libtomcrypt_dep])
system_ss.add(when: 'CONFIG_OT_COMMON', if_true: files('ot_common.c'))
system_ss.add(when: 'CONFIG_OT_CSRNG', if_true: [files('ot_csrng.c'), libtomcrypt_dep])
system_ss.add(when: 'CONFIG_OT_EDN', if_true: files('ot_edn.c'))
system_ss.add(when: 'CONFIG_OT_ENTROPY_SRC', if_true: [files('ot_entropy_src.c'), libtomcrypt_dep])
system_ss.add(when: 'CONFIG_OT_FLASH', if_true: files('ot_flash.c'))
system_ss.add(when: 'CONFIG_OT_HMAC', if_true: [files('ot_hmac.c'), libtomcrypt_dep])
# system_ss.add(when: 'CONFIG_OT_IBEX_WRAPPER', if_true: files('ot_ibex_wrapper.c'))
# system_ss.add(when: 'CONFIG_OT_IBEX_WRAPPER_EG', if_true: files('ot_ibex_wrapper_eg.c'))
system_ss.add(when: 'CONFIG_OT_KEYMGR', if_true: files('ot_keymgr.c'))
system_ss.add(when: 'CONFIG_OT_KMAC', if_true: [files('ot_kmac.c'), libtomcrypt_dep])
system_ss.add(when: 'CONFIG_OT_OTBN', if_true: files('ot_otbn.c'))
# system_ss.add(when: 'CONFIG_OT_OTP', if_true: files('ot_otp.c'))
# system_ss.add(when: 'CONFIG_OT_OTP_BE_IF', if_true: files('ot_otp_be_if.c'))
# system_ss.add(when: 'CONFIG_OT_OTP_EG', if_true: files('ot_otp_eg.c'))
# system_ss.add(when: 'CONFIG_OT_OTP_OT_BE', if_true: files('ot_otp_ot_be.c'))
system_ss.add(when: 'CONFIG_OT_PCR', if_true: [files('ot_pcr.c'), libtomcrypt_dep])
system_ss.add(when: 'CONFIG_OT_PRINCE', if_true: files('ot_prince.c'))
system_ss.add(when: 'CONFIG_OT_PRNG', if_true: files('ot_prng.c'))
system_ss.add(when: 'CONFIG_OT_RANDOM_SRC', if_true: files('ot_random_src.c'))
system_ss.add(when: 'CONFIG_OT_ROM_CTRL', if_true: files('ot_rom_ctrl.c', 'ot_rom_ctrl_img.c'))
system_ss.add(when: 'CONFIG_OT_SM4', if_true: files('ot_sm4.c'))

subdir('otbn')
