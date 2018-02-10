{
    'targets': [
    {
      'target_name': 'lzma',
      'type': 'shared_library',
      'dependencies': [
        '<(DEPTH)/third_party/android_crazy_linker/crazy_linker.gyp:crazy_linker',
      ],
      'include_dirs': [
        '../..',
        '<(DEPTH)/third_party/lzma/src/linker',
        '<(DEPTH)/third_party/lzma/src/linker/include',
        '<(DEPTH)/third_party/lzma',
      ],
      'cflags!': [ '-Werror', '-Wall', '-std=gnu99' ],
      'cflags_cc': [ '-std=c++11'],
      'link_settings': {
        'ldflags': [
        ],
        'libraries': [
          '-llog',
          '-landroid',
        ],
        'libraries!': [
            '-lstdc++',
        ],
      },
      'sources': [
          'src/LzmaUtil.c',
          '7zC/Alloc.c',
          '7zC/LzFind.c',
          '7zC/LzmaDec.c',
          '7zC/7zFile.c',
          '7zC/7zStream.c',
      ],
    },
    {
      'target_name': 'lzma_java',
      'type': 'none',
      'dependencies': [
      ],
      'variables': {
        'java_in_dir': 'java',
        'has_java_resources': 0,
        'R_package': 'com.samtest',
        'R_package_relpath': 'com/samtest',
      },
      'includes': [ '../../build/java.gypi' ],
    },
    ],  # targets
}
