project('bitflags', 'rust', version: '1.3.2')

bitflags_lib = static_library('bitflags',
                              'src/lib.rs',
                              install: true)

bitflags_dep = declare_dependency(link_with: bitflags_lib)
