# nyxFault-Binja

[![GitHub license](https://img.shields.io/github/license/nyxFault/nyxFault-Binja.svg?style=for-the-badge)](https://github.com/nyxFault/nyxFault-Binja/blob/main/LICENSE)
![Python](https://img.shields.io/badge/Python-3.x-blue.svg?style=for-the-badge)
[![Last Commit](https://img.shields.io/github/last-commit/nyxFault/nyxFault-Binja.svg?style=for-the-badge)](https://github.com/nyxFault/nyxFault-Binja)
![Binary Ninja](https://img.shields.io/badge/Binary%20Ninja-Plugin-blue?style=for-the-badge)


A collection of Binary Ninja plugins designed to streamline and enhance your reverse-engineering workflow. These tools simplify common tasks, automate repetitive actions, and introduce new capabilities that extend Binary Ninja’s functionality. I built these plugins while learning Binary Ninja and I personally liked its Python API very much and decided to develop some plugins to gain hands-on experience. I have developed few basic plugins.

## Installation

Clone this repository into your Binary Ninja **plugins** directory.

### Windows

```bash
cd "%APPDATA%\Binary Ninja\plugins\"
git clone https://github.com/nyxFault/nyxFault-Binja
```
This will produce a path similar to:

```bash
C:\Users\<yourname>\AppData\Roaming\Binary Ninja\plugins\nyxFault-Binja
```

### Linux

```bash
cd ~/.binaryninja/plugins/
git clone https://github.com/nyxFault/nyxFault-Binja
```

After cloning, restart Binary Ninja and the plugins should load automatically.

To verify that the plugin loaded successfully, check the Log panel.
You should see messages similar to:

```txt
[ScriptingProvider] [nyxfault_plugins] Plugin loaded.
[PythonPlugin] Loaded python3 plugin 'nyxFault-Binja'
```

### Usage

You can access the plugins in two ways:

#### 1. Through the Plugins Menu

Navigate to:

**Plugins → nyxFault-Binja**

It should look like this:

![Plugin](https://github.com/nyxFault/Images/blob/main/image.png?raw=true)

#### 2. Through the Command Palette

Press **Ctrl + P** to open the Command Palette,
type _nyxFault_, and select the desired plugin from the filtered list.


## Callees Graph

![Callee](https://github.com/nyxFault/Images/blob/main/callees.png?raw=true)

## Callers Graph

![Caller](https://github.com/nyxFault/Images/blob/main/callers.png?raw=true)

## External Symbols

![ExternalSymbols](https://github.com/nyxFault/Images/blob/main/External_Symbol.png?raw=true)

## Functions Symbols

![FunctionSymbols](https://github.com/nyxFault/Images/blob/main/Functions_Symbol.png?raw=true)

## Import Address Symbols

![ImportAddressSymbols](https://github.com/nyxFault/Images/blob/main/Import_Address_Symbols.png?raw=true)

## Import Function Symbols

![ImportFunctionSymbols](https://github.com/nyxFault/Images/blob/main/Import_Function_Symbols.png?raw=true)

## Symbolic Function Symbols

![SymbolicFunctionSymbols](https://github.com/nyxFault/Images/blob/main/Symbolic_Function_Symbol.png?raw=true)

## Sections

![Sections](https://github.com/nyxFault/Images/blob/main/sections.png?raw=true)

## Segments

![Segments](https://github.com/nyxFault/Images/blob/main/segments.png?raw=true)

## IOCTL Decoder

A Windows Device I/O Control (IOCTL) code decoder plugin for Binary Ninja. This tool helps reverse engineers quickly decode and understand Windows IOCTL codes found during driver analysis.

**Navigate to Plugins → nyxFault-Binja → Windows IOCTL Decoder**

![IOCTLDecoder](https://github.com/nyxFault/Images/blob/main/IOCTL.png?raw=true)

**Credits**

- Based on work by Satoshi Tanda [WinIoCtlDecoder](https://github.com/tandasat/WinIoCtlDecoder)
- Device type mapping from [OSR Online](https://www.osronline.com/article.cfm^article=229.htm)



