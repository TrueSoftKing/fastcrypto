```
cargo build --bin mnemonics-cli

# to generate a new one

target/debug/mnemonics-cli generate

12 word mnemonic: "island forget poverty solution rate proud clever kit citizen kid govern course"
pk: QnAGAjBsRiK0kLX0zm57Cgb/xLeMMqgwqPhqDtHiSWA=
Entropy: [118, 107, 106, 164, 103, 107, 35, 89, 138, 163, 215, 41, 79, 73, 148, 24]
8 word mnemonic: "3790word-3 3413word-4 3310word-3 1132word-1 4437word-3 6886word-1 2538word-1 4740word-0 "

# to convert a partial 8-word to 12-word with a target pk

target/debug/mnemonics-cli convert-mnemonics --short "3790word 3413word 3310word 1132word 4437word 6886word 2538word 4740word" --target-pk QnAGAjBsRiK0kLX0zm57Cgb/xLeMMqgwqPhqDtHiSWA=


```