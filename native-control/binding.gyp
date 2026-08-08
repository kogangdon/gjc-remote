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
      "configurations": {
        "Release": {
          "msvs_settings": {
            "VCCLCompilerTool": { "AdditionalOptions=": [] },
            "VCLibrarianTool": { "AdditionalOptions=": [] },
            "VCLinkerTool": { "AdditionalOptions=": [] }
          }
        }
      },
      "conditions": [
        ["OS=='win'", { "libraries": [ "-ladvapi32" ] }],
        ["OS=='linux'", { "libraries": [ "-lacl" ] }]
      ]
    }
  ]
}
