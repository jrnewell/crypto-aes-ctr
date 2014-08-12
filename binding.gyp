{
  "targets": [
    {
      "target_name": "addon",
      "sources": [ "addon.cc", "open_ssl_wrapper.cc" ],
      'conditions': [
        [ 'OS=="win"', {
          'conditions': [
            # "openssl_root" is the directory on Windows of the OpenSSL files
            ['target_arch=="x64"', {
              'variables': {
                'openssl_root%': 'C:/OpenSSL-Win64'
              },
            }, {
              'variables': {
                'openssl_root%': 'C:/OpenSSL-Win32'
              },
            }],
          ],
          'defines': [
            'uint=unsigned int',
          ],
          'libraries': [
            '-l<(openssl_root)/lib/libeay32.lib'
          ],
          'include_dirs': [
            '<(openssl_root)/include',
          ],
        },
        # Otherwise, if not Windows, link against the exposed OpenSSL
        # in Node.
          {
          "conditions": [
            ['node_shared_openssl=="false"', {
              # so when "node_shared_openssl" is "false", then OpenSSL has been
              # bundled into the node executable. So we need to include the same
              # header files that were used when building node.
              'include_dirs': [
                '<(node_root_dir)/deps/openssl/openssl/include'
              ],
              "conditions" : [
                ["target_arch=='ia32'", {
                  "include_dirs": [ "<(node_root_dir)/deps/openssl/config/piii" ]
                }],
                ["target_arch=='x64'", {
                  "include_dirs": [ "<(node_root_dir)/deps/openssl/config/k8" ]
                }],
                ["target_arch=='arm'", {
                  "include_dirs": [ "<(node_root_dir)/deps/openssl/config/arm" ]
                }]
              ]
            }]]}
        ],
      ]
    }
  ]
}
