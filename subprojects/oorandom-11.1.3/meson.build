project('oorandom', 'rust', version: '11.1.3')

oorandom_lib = static_library('oorandom',
                              'src/lib.rs',
                              install: true)

oorandom_dep = declare_dependency(link_with: oorandom_lib)
