{
  "targets": [
    {
      "target_name": "native_control",
      "sources": [ "src/addon.cc" ],
      "cflags_cc": [ "-std=c++17" ],
      "msvs_settings": {
        "VCCLCompilerTool": { "AdditionalOptions": [ "/std:c++17" ] }
      },
      "defines": [ "NAPI_VERSION=8" ],
      "conditions": [
        ["OS=='win'", { "libraries": [ "-ladvapi32" ] }],
        ["OS=='linux'", { "libraries": [ "-lacl" ] }]
      ]
    }
  ]
}
