project('ethnum', 'rust', version: '1.3.2')

ethnum_lib = static_library('ethnum',
                            'src/lib.rs',
                            override_options: ['rust_std=2021'],
                            install: true)

ethnum_dep = declare_dependency(link_with: ethnum_lib)
