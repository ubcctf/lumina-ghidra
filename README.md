# lumina-ghidra
Ghidra port for [lumina-binja](https://github.com/ubcctf/lumina-binja), a reimplmentation of IDA's [Lumina](https://hex-rays.com/products/ida/lumina/) feature in Binary Ninja

The features provided by this port is on par with the Binary Ninja plugin - see the [repo](https://github.com/ubcctf/lumina-binja) for more info!

**CURRENTLY IN ACTIVE DEVELOPMENT - NOTHING IS FULLY STABLE YET**

## Building and Installation
 - include `--recurse-submodules` to get the Ghidrathon repo when cloning this repo
 - `cd Ghidrathon && git checkout pre-10.2 0a54fa1cef41869582eb3614a86a9475ecf5c67a` if you are running Ghidra < v10.2
 - `gradle -PGHIDRA_INSTALL_DIR=<absolute path to Ghidra install>` should compile both Ghidrathon (in `Ghidrathon/dist/`) and this plugin (in `dist/`)
 - Alternatively, if you are using `EclipseDev`, import the project, right click the project: `GhidraDev -> Link Ghidra...`, follow the prompts, and then `GhidraDev -> Export -> Ghidra Module Extension...` which will do the same thing as the command above
 - Go into Ghidra, `File -> Install Extensions`, click the green arrow and select both of the zip file
 - Check both of the new extensions and restart Ghidra
 - Configure Lumina through `Edit -> Tool Options -> Lumina` in disassembler view; Most logs will be viewable in the main Ghidra tool -> `Help -> Show Log`

## Running tests
The `test.py` requires more setup than the Binary Ninja counterpart, mainly because of the way headless mode works for Ghidra:
 - Make sure Ghidrathon is set up, and requirements are installed (along with `frida`)
 - Run `analyzeHeadless <project path> <project name> -import <name> -scriptPath <repo root dir> -postScript test.py` - This would require you to erase the `<project name>.gpr` file every single time since Ghidra does not allow reimporting
 - Alternatively you can run `analyzeHeadless <project path> <project name> -import <name>` once, and then `analyzeHeadless <project path> <project name> -process <name> -scriptPath <repo root dir> -postScript test.py` to use the cached analysis (faster, but things might persist in the project that is unideal for testing)
 - You'll need to input the filepath and verbosity arguments through stdin, along with manually finding IDA addresses for `calc_func_metadata`, `MD5Update` and `MD5Final` - `postScript` argument passing doesn't seem to work that well, and we cannot really analyze multiple binaries needed to get the addresses automatically without prior setup with `analyzeHeadless` either


