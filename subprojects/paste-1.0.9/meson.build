project('paste', 'rust', version: '1.0.49')

paste_lib = shared_library('paste',
                           'src/lib.rs',
                            rust_crate_type: 'proc-macro')

paste_dep = declare_dependency(link_with: paste_lib)
